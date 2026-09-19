use std::env;
use std::fs;
use std::net::{TcpListener, TcpStream};

use rand_core::OsRng;
use signature::{Keypair, Signer};
use slh_dsa::SigningKey;
use token_core::{ReadFrameError, SigningBackend};

macro_rules! dev_backend {
    ($($variant:ident => $ty:ty, $name:literal;)+) => {
        enum DevBackend {
            $($variant(SigningKey<$ty>, Vec<u8>)),+
        }

        impl DevBackend {
            fn from_key_files(param_set_name: &str, sec_key: &[u8], pub_key: &[u8]) -> Result<Self, String> {
                match param_set_name {
                    $(
                        $name => {
                            let signing_key = SigningKey::<$ty>::try_from(sec_key)
                                .map_err(|_| format!("invalid secret key for parameter set '{}'", $name))?;
                            Ok(DevBackend::$variant(signing_key, pub_key.to_vec()))
                        }
                    )+
                    other => Err(format!(
                        "unknown parameter set '{other}' (expected one of: 128s, 128f, 192s, 192f, 256s, 256f)"
                    )),
                }
            }
        }

        impl SigningBackend for DevBackend {
            fn param_set_name(&self) -> &str {
                match self {
                    $(DevBackend::$variant(..) => $name),+
                }
            }

            fn public_key(&self) -> &[u8] {
                match self {
                    $(DevBackend::$variant(_, pk) => pk),+
                }
            }

            fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, ()> {
                match self {
                    $(
                        DevBackend::$variant(signing_key, _) => {
                            let signature = signing_key.try_sign(message).map_err(|_| ())?;
                            let sig_bytes = signature.to_bytes();
                            if out.len() < sig_bytes.len() {
                                return Err(());
                            }
                            out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
                            Ok(sig_bytes.len())
                        }
                    )+
                }
            }

            fn generate_keypair(&mut self) -> bool {
                match self {
                    $(
                        DevBackend::$variant(signing_key, public_key_bytes) => {
                            let mut rng = OsRng;
                            let new_key = SigningKey::<$ty>::new(&mut rng);
                            *public_key_bytes = new_key.verifying_key().to_bytes().to_vec();
                            *signing_key = new_key;
                            true
                        }
                    )+
                }
            }
        }
    };
}

dev_backend! {
    Sha2_128s => slh_dsa::Sha2_128s, "128s";
    Sha2_128f => slh_dsa::Sha2_128f, "128f";
    Sha2_192s => slh_dsa::Sha2_192s, "192s";
    Sha2_192f => slh_dsa::Sha2_192f, "192f";
    Sha2_256s => slh_dsa::Sha2_256s, "256s";
    Sha2_256f => slh_dsa::Sha2_256f, "256f";
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

const MAX_MESSAGE_LEN: usize = 1024 * 1024;
const REQUEST_BUF_LEN: usize = 1 + 4 + MAX_MESSAGE_LEN;
const RESPONSE_BUF_LEN: usize = 65536;

fn main() {
    let param_set_name = env_or("PARAM_SET", "192f");
    let sec_key_path = env_or("SEC_KEY_PATH", "keys/sec.key");
    let pub_key_path = env_or("PUB_KEY_PATH", "keys/pub.key");
    let port: u16 = env_or("PORT", "7878")
        .parse()
        .expect("PORT must be a valid u16");

    let sec_key = fs::read(&sec_key_path)
        .unwrap_or_else(|e| panic!("failed to read secret key at {sec_key_path}: {e}"));
    let pub_key = fs::read(&pub_key_path)
        .unwrap_or_else(|e| panic!("failed to read public key at {pub_key_path}: {e}"));

    let mut backend = DevBackend::from_key_files(&param_set_name, &sec_key, &pub_key)
        .unwrap_or_else(|e| panic!("{e}"));

    let listener = TcpListener::bind(("0.0.0.0", port))
        .unwrap_or_else(|e| panic!("failed to bind 0.0.0.0:{port}: {e}"));

    println!(
        "dev-signer listening on 0.0.0.0:{port} (param set {param_set_name}, public key {} bytes)",
        backend.public_key().len()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("client connected: {:?}", stream.peer_addr());
                handle_connection(stream, &mut backend);
                println!("client disconnected");
            }
            Err(e) => eprintln!("connection failed: {e}"),
        }
    }
}


fn handle_connection(mut stream: TcpStream, backend: &mut DevBackend) {
    let mut request_buf = vec![0u8; REQUEST_BUF_LEN];
    let mut response_buf = vec![0u8; RESPONSE_BUF_LEN];

    loop {
        let (command_byte, payload) = match token_core::read_frame(&mut stream, &mut request_buf) {
            Ok(frame) => frame,
            Err(ReadFrameError::Io(_)) => return,
            Err(ReadFrameError::FrameTooLarge { declared, max }) => {
                eprintln!("dropped oversized frame: declared {declared} bytes, max {max}");
                continue;
            }
        };

        let (status, len) = token_core::dispatch(command_byte, payload, backend, &mut response_buf);

        if let Err(e) = token_core::write_frame(&mut stream, status.into(), &response_buf[..len]) {
            eprintln!("failed to write response: {e}");
            return;
        }
    }
}
