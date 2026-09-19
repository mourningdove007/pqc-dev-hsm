#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use core::convert::Infallible;

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

static SECRET_KEY_BYTES: &[u8] = include_bytes!("../../keys/sec.key");
static PUBLIC_KEY_BYTES: &[u8] = include_bytes!("../../keys/pub.key");

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

impl NanoBackend {
    fn from_embedded() -> Self {
        let signing_key = SigningKey::<SelectedParams>::try_from(SECRET_KEY_BYTES)
            .expect("embedded secret key must be well-formed");
        let mut public_key_bytes = [0u8; PUBLIC_KEY_LEN];
        public_key_bytes.copy_from_slice(PUBLIC_KEY_BYTES);
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

const SUCCESS_HOLD: Duration = Duration::from_millis(3000);

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

    let mut backend = NanoBackend::from_embedded();

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
