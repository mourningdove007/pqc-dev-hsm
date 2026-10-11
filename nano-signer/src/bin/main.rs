#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use core::convert::Infallible;

use embedded_storage::{ReadStorage, Storage};
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::main;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::sha::Sha;
use esp_hal::time::{Duration, Instant};
use esp_hal::usb_serial_jtag::UsbSerialJtag;
use esp_hal::Blocking;
use slh_dsa_hw::signature::Signer;
use slh_dsa_hw::SigningKey;
use token_core::{Command, SigningBackend, Status};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(feature = "param-128s")]
type SelectedParams = slh_dsa_hw::Sha2_128s;
#[cfg(feature = "param-128f")]
type SelectedParams = slh_dsa_hw::Sha2_128f;
#[cfg(feature = "param-192s")]
type SelectedParams = slh_dsa_hw::Sha2_192s;
#[cfg(feature = "param-192f")]
type SelectedParams = slh_dsa_hw::Sha2_192f;
#[cfg(feature = "param-256s")]
type SelectedParams = slh_dsa_hw::Sha2_256s;
#[cfg(feature = "param-256f")]
type SelectedParams = slh_dsa_hw::Sha2_256f;

#[cfg(not(any(
    feature = "param-128s",
    feature = "param-128f",
    feature = "param-192s",
    feature = "param-192f",
    feature = "param-256s",
    feature = "param-256f",
)))]
compile_error!("enable exactly one param-* feature, e.g. --features param-192f");

#[cfg(feature = "param-128s")]
const PARAM_SET_NAME: &str = "128s";
#[cfg(feature = "param-128f")]
const PARAM_SET_NAME: &str = "128f";
#[cfg(feature = "param-192s")]
const PARAM_SET_NAME: &str = "192s";
#[cfg(feature = "param-192f")]
const PARAM_SET_NAME: &str = "192f";
#[cfg(feature = "param-256s")]
const PARAM_SET_NAME: &str = "256s";
#[cfg(feature = "param-256f")]
const PARAM_SET_NAME: &str = "256f";


#[cfg(feature = "param-128s")]
const PUBLIC_KEY_LEN: usize = 32;
#[cfg(feature = "param-128f")]
const PUBLIC_KEY_LEN: usize = 32;
#[cfg(feature = "param-192s")]
const PUBLIC_KEY_LEN: usize = 48;
#[cfg(feature = "param-192f")]
const PUBLIC_KEY_LEN: usize = 48;
#[cfg(feature = "param-256s")]
const PUBLIC_KEY_LEN: usize = 64;
#[cfg(feature = "param-256f")]
const PUBLIC_KEY_LEN: usize = 64;

#[cfg(feature = "param-128s")]
const SIGNATURE_MAX_LEN: usize = 7856;
#[cfg(feature = "param-128f")]
const SIGNATURE_MAX_LEN: usize = 17088;
#[cfg(feature = "param-192s")]
const SIGNATURE_MAX_LEN: usize = 16224;
#[cfg(feature = "param-192f")]
const SIGNATURE_MAX_LEN: usize = 35664;
#[cfg(feature = "param-256s")]
const SIGNATURE_MAX_LEN: usize = 29792;
#[cfg(feature = "param-256f")]
const SIGNATURE_MAX_LEN: usize = 49856;


const MAX_MESSAGE_LEN: usize = 4096;
const REQUEST_BUF_LEN: usize = 1 + 4 + MAX_MESSAGE_LEN;
const RESPONSE_BUF_LEN: usize = SIGNATURE_MAX_LEN;

/// Persisted-record layout in the `keys` flash partition (see
/// `partitions.csv`): 1-byte magic, 2-byte little-endian secret-key length,
/// 2-byte little-endian public-key length, then the secret key bytes
/// immediately followed by the public key bytes. `KEY_RECORD_MAGIC` can
/// never collide with erased flash, which always reads back as `0xFF`.
const KEY_RECORD_MAGIC: u8 = 0xA5;
const KEY_RECORD_HEADER_LEN: usize = 5;
/// Generously covers the largest FIPS 205 SLH-DSA-SHA2 secret+public key
/// pair (256f: 128-byte secret key + 64-byte public key = 192 bytes).
const MAX_KEY_RECORD_LEN: usize = 512;

esp_bootloader_esp_idf::esp_app_desc!();

struct SerialTransport(UsbSerialJtag<'static, Blocking>);

impl token_core::Read for SerialTransport {
    type Error = Infallible;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        for slot in buf.iter_mut() {
            *slot = nb::block!(self.0.read_byte())?;
        }
        Ok(())
    }
}

impl token_core::Write for SerialTransport {
    type Error = Infallible;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.0.write(buf)
    }
}

struct NanoBackend {
    signing_key: SigningKey<SelectedParams>,
    public_key_bytes: [u8; PUBLIC_KEY_LEN],
}

/// Finds the `keys` partition (see `partitions.csv`) and returns a
/// `FlashRegion` view into it.
fn find_keys_partition<'a, 'd>(
    flash: &'a mut esp_storage::FlashStorage<'d>,
    table_buf: &'a mut [u8; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN],
) -> esp_bootloader_esp_idf::partitions::FlashRegion<'a, esp_storage::FlashStorage<'d>> {
    let table = esp_bootloader_esp_idf::partitions::read_partition_table(flash, table_buf)
        .expect("failed to read partition table");
    table
        .iter()
        .find(|entry| entry.label_as_str() == "keys")
        .expect("no `keys` partition defined; check partitions.csv and the --partition-table flag")
        .as_embedded_storage(flash)
}

/// Loads a persisted keypair from the `keys` flash partition, or generates a
/// fresh one and persists it if the partition has no valid record yet
fn load_or_generate_keys<'a, 'd>(
    flash: &'a mut esp_storage::FlashStorage<'d>,
    table_buf: &'a mut [u8; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN],
) -> (SigningKey<SelectedParams>, [u8; PUBLIC_KEY_LEN]) {
    let mut region = find_keys_partition(flash, table_buf);

    let mut record = [0u8; MAX_KEY_RECORD_LEN];
    region
        .read(0, &mut record)
        .expect("failed to read keys partition");

    if record[0] == KEY_RECORD_MAGIC {
        let sec_len = u16::from_le_bytes([record[1], record[2]]) as usize;
        let pub_len = u16::from_le_bytes([record[3], record[4]]) as usize;
        let sec_start = KEY_RECORD_HEADER_LEN;
        let pub_start = sec_start + sec_len;
        let signing_key =
            SigningKey::<SelectedParams>::try_from(&record[sec_start..sec_start + sec_len])
                .expect("stored secret key is corrupt");
        let mut public_key_bytes = [0u8; PUBLIC_KEY_LEN];
        public_key_bytes.copy_from_slice(&record[pub_start..pub_start + pub_len]);
        (signing_key, public_key_bytes)
    } else {
        let mut trng = Trng::try_new().expect("failed to init RNG for key generation");
        let signing_key = SigningKey::<SelectedParams>::new(&mut trng);
        let sec_bytes = signing_key.to_bytes();
        let pub_bytes = signing_key.as_ref().to_bytes();

        let mut record = [0xFFu8; MAX_KEY_RECORD_LEN];
        record[0] = KEY_RECORD_MAGIC;
        record[1..3].copy_from_slice(&(sec_bytes.len() as u16).to_le_bytes());
        record[3..5].copy_from_slice(&(pub_bytes.len() as u16).to_le_bytes());
        let sec_start = KEY_RECORD_HEADER_LEN;
        let pub_start = sec_start + sec_bytes.len();
        record[sec_start..pub_start].copy_from_slice(&sec_bytes);
        record[pub_start..pub_start + pub_bytes.len()].copy_from_slice(&pub_bytes);
        region
            .write(0, &record)
            .expect("failed to write keys partition");

        let mut public_key_bytes = [0u8; PUBLIC_KEY_LEN];
        public_key_bytes.copy_from_slice(&pub_bytes);
        (signing_key, public_key_bytes)
    }
}

impl NanoBackend {
    /// `flash_peripheral` is `peripherals.FLASH` from `esp_hal::init()` in
    /// `main()`; `FlashStorage::new` takes it by value.
    fn from_flash_or_generate(flash_peripheral: esp_hal::peripherals::FLASH<'static>) -> Self {
        let mut flash = esp_storage::FlashStorage::new(flash_peripheral);
        let mut table_buf = [0u8; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN];
        let (signing_key, public_key_bytes) = load_or_generate_keys(&mut flash, &mut table_buf);
        Self {
            signing_key,
            public_key_bytes,
        }
    }
}

impl SigningBackend for NanoBackend {
    fn param_set_name(&self) -> &str {
        PARAM_SET_NAME
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        let signature = self.signing_key.try_sign(message).map_err(|_| ())?;
        let sig_bytes = signature.to_bytes();
        if out.len() < sig_bytes.len() {
            return Err(());
        }
        out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }

    fn generate_keypair(&mut self) -> bool {
        let Ok(mut trng) = Trng::try_new() else {
            return false;
        };
        let new_key = SigningKey::<SelectedParams>::new(&mut trng);
        self.public_key_bytes
            .copy_from_slice(&new_key.as_ref().to_bytes());
        self.signing_key = new_key;
        true
    }
}

const SUCCESS_HOLD: Duration = Duration::from_millis(200);

fn flash_success(led: &mut Output<'_>) {
    led.set_low();
    let hold_until = Instant::now() + SUCCESS_HOLD;
    while Instant::now() < hold_until {}
    led.set_high();
}

#[allow(
    clippy::large_stack_frames,
    reason = "request_buf and response_buf are sized for this build's parameter set and \
    live for the lifetime of main; not unusual on a 512 KB-RAM chip."
)]
#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    let _ = peripherals.GPIO27;
    let _ = peripherals.GPIO28;
    let _ = peripherals.GPIO29;
    let _ = peripherals.GPIO30;
    let _ = peripherals.GPIO31;
    let _ = peripherals.GPIO32;

    let mut red = Output::new(peripherals.GPIO46, Level::High, OutputConfig::default());
    let mut green = Output::new(peripherals.GPIO0, Level::High, OutputConfig::default());
    let mut blue = Output::new(peripherals.GPIO45, Level::High, OutputConfig::default());

    let mut transport = SerialTransport(UsbSerialJtag::new(peripherals.USB_DEVICE));

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);

    slh_dsa_hw::init_hw_sha(Sha::new(peripherals.SHA));

    let mut backend = NanoBackend::from_flash_or_generate(peripherals.FLASH);

    let mut request_buf = [0u8; REQUEST_BUF_LEN];
    let mut response_buf = [0u8; RESPONSE_BUF_LEN];

    loop {
        let (command_byte, payload) =
            match token_core::read_frame(&mut transport, &mut request_buf) {
                Ok(frame) => frame,
                Err(_) => continue,
            };

        let visual_feedback = command_byte == Command::Sign as u8
            || command_byte == Command::GenerateKeypair as u8;

        if visual_feedback {
            
            red.set_high();
            blue.set_low();
        }

        let (status, len) =
            token_core::dispatch(command_byte, payload, &mut backend, &mut response_buf);

        if visual_feedback {
            blue.set_high();
            match status {
                Status::Ok => flash_success(&mut green),
                _ => red.set_low(),
            }
        }

        let _ = token_core::write_frame(&mut transport, status.into(), &response_buf[..len]);
    }
}
