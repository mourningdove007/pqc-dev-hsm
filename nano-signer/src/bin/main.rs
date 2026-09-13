#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use core::fmt::Write as _;

use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::main;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::sha::Sha;
use esp_hal::time::{Duration, Instant};
use esp_hal::usb_serial_jtag::UsbSerialJtag;
use slh_dsa_hw::signature::Signer;
use slh_dsa_hw::SigningKey;

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

static SECRET_KEY_BYTES: &[u8] = include_bytes!("../../keys/sec.key");
static PUBLIC_KEY_BYTES: &[u8] = include_bytes!("../../keys/pub.key");
static MESSAGE: &[u8] = b"hello from the nano-signer bring-up test";

esp_bootloader_esp_idf::esp_app_desc!();

#[allow(
    clippy::large_stack_frames,
    reason = "it's not unusual to allocate larger buffers etc. in main"
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
    let mut orange = Output::new(peripherals.GPIO48, Level::High, OutputConfig::default());

    let mut usb_serial = UsbSerialJtag::new(peripherals.USB_DEVICE);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);

    slh_dsa_hw::init_hw_sha(Sha::new(peripherals.SHA));

    loop {
        let Ok(byte) = usb_serial.read_byte() else {
            continue;
        };

        match byte {
            b'r' => red.toggle(),
            b'g' => green.toggle(),
            b'b' => blue.toggle(),
            b'o' => orange.toggle(),
            b's' => {
                blue.set_low();

                let signing_key = SigningKey::<SelectedParams>::try_from(SECRET_KEY_BYTES)
                    .expect("embedded secret key must be well-formed");

                match signing_key.try_sign(MESSAGE) {
                    Ok(signature) => {
                        blue.set_high();

                        let sig_bytes = signature.to_bytes();
                        let _ = write!(
                            usb_serial,
                            "signed {} bytes with public key ({PARAM_SET_NAME}) ",
                            MESSAGE.len(),
                        );
                        for b in PUBLIC_KEY_BYTES.iter() {
                            let _ = write!(usb_serial, "{b:02x}");
                        }
                        let _ = write!(usb_serial, "\r\nsignature ({} bytes): ", sig_bytes.len());
                        for b in sig_bytes.iter() {
                            let _ = write!(usb_serial, "{b:02x}");
                        }
                        let _ = write!(usb_serial, "\r\n");
                        let _ = usb_serial.flush_tx();

                        green.set_low();
                        let hold_until = Instant::now() + Duration::from_millis(500);
                        while Instant::now() < hold_until {}
                        green.set_high();
                    }
                    Err(_) => {
                        blue.set_high();
                        let _ = write!(usb_serial, "signing failed\r\n");
                        let _ = usb_serial.flush_tx();

                        red.set_low();
                        let hold_until = Instant::now() + Duration::from_millis(500);
                        while Instant::now() < hold_until {}
                        red.set_high();
                    }
                }
            }
            b'k' => {
                red.set_low();
                blue.set_low();

                let Ok(mut trng) = Trng::try_new() else {
                    red.set_high();
                    blue.set_high();
                    let _ = write!(usb_serial, "TRNG unavailable\r\n");
                    let _ = usb_serial.flush_tx();
                    continue;
                };

                let signing_key = SigningKey::<SelectedParams>::new(&mut trng);
                let sec_bytes = signing_key.to_bytes();
                let pub_bytes = signing_key.as_ref().to_bytes();

                red.set_high();
                blue.set_high();

                let _ = write!(
                    usb_serial,
                    "generated with {PARAM_SET_NAME}\r\nsec.key ({} bytes): ",
                    sec_bytes.len()
                );
                for b in sec_bytes.iter() {
                    let _ = write!(usb_serial, "{b:02x}");
                }
                let _ = write!(usb_serial, "\r\npub.key ({} bytes): ", pub_bytes.len());
                for b in pub_bytes.iter() {
                    let _ = write!(usb_serial, "{b:02x}");
                }
                let _ = write!(usb_serial, "\r\nnot written to storage yet\r\n");
                let _ = usb_serial.flush_tx();

                green.set_low();
                let hold_until = Instant::now() + Duration::from_millis(500);
                while Instant::now() < hold_until {}
                green.set_high();
            }
            b'x' => {
                red.set_high();
                green.set_high();
                blue.set_high();
                orange.set_high();
            }
            b'?' => {
                let profile = if cfg!(debug_assertions) { "dev" } else { "release" };
                let _ = write!(
                    usb_serial,
                    "profile={profile} param={PARAM_SET_NAME} red={:?} green={:?} blue={:?} orange={:?}\r\n",
                    red.output_level(),
                    green.output_level(),
                    blue.output_level(),
                    orange.output_level(),
                );
                let _ = usb_serial.flush_tx();
            }
            _ => {}
        }
    }
}
