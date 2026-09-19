use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use signature::Verifier;
use slh_dsa::{Sha2_192f, Signature, VerifyingKey};

const TEST_PORT: u16 = 17879;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

struct DevSigner(Child);

impl Drop for DevSigner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_dev_signer() -> DevSigner {
    let repo_root = manifest_dir().join("..");
    let dev_signer_manifest = repo_root.join("dev-signer/Cargo.toml");
    let sec_key = repo_root.join("dev-signer/keys/sec.key");
    let pub_key = repo_root.join("dev-signer/keys/pub.key");

    let child = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(&dev_signer_manifest)
        .env("PORT", TEST_PORT.to_string())
        .env("SEC_KEY_PATH", &sec_key)
        .env("PUB_KEY_PATH", &pub_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn dev-signer");

    wait_for_port(TEST_PORT);
    DevSigner(child)
}

fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("dev-signer never started listening on 127.0.0.1:{port}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}


fn provider_path() -> PathBuf {
    let file_name = format!(
        "{}pkcs11_provider{}{}",
        std::env::consts::DLL_PREFIX,
        if std::env::consts::DLL_EXTENSION.is_empty() {
            ""
        } else {
            "."
        },
        std::env::consts::DLL_EXTENSION
    );

    for profile in ["debug", "release"] {
        let candidate = manifest_dir().join("target").join(profile).join(&file_name);
        if candidate.exists() {
            return candidate;
        }
    }

    panic!("could not find built {file_name} under target/debug or target/release");
}

#[test]
fn sign_a_message_over_pkcs11_against_dev_signer() {
    let _dev_signer = spawn_dev_signer();
    
    unsafe {
        std::env::set_var("PQC_HSM_ENDPOINT", format!("tcp://127.0.0.1:{TEST_PORT}"));
    }

    let pkcs11 = Pkcs11::new(provider_path()).expect("failed to load pkcs11-provider");
    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .expect("C_Initialize failed");

    let slot = pkcs11.get_slots_with_token().expect("C_GetSlotList failed")[0];
    let session = pkcs11.open_ro_session(slot).expect("C_OpenSession failed");

    let private_keys = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .expect("C_FindObjects (private key) failed");
    assert_eq!(private_keys.len(), 1, "expected exactly one private key object");
    let private_key = private_keys[0];

    let mechanism_type =
        MechanismType::new_vendor_defined(pkcs11_provider::CKM_SLH_DSA_SHA2_VENDOR)
            .expect("mechanism type construction failed");
    let mechanism =
        Mechanism::VendorDefined(VendorDefinedMechanism::new::<()>(mechanism_type, None));

    let message = b"send a value over PKCS#11 and get a signature back";
    let signature_bytes = session
        .sign(&mechanism, private_key, message)
        .expect("C_Sign failed");
    assert_eq!(
        signature_bytes.len(),
        35664,
        "unexpected signature length for the 192f parameter set"
    );

    let public_keys = session
        .find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])
        .expect("C_FindObjects (public key) failed");
    assert_eq!(public_keys.len(), 1, "expected exactly one public key object");

    let attrs = session
        .get_attributes(public_keys[0], &[AttributeType::Value])
        .expect("C_GetAttributeValue failed");
    let Attribute::Value(public_key_bytes) = &attrs[0] else {
        panic!("expected a CKA_VALUE attribute back");
    };

    let expected_public_key = std::fs::read(manifest_dir().join("../dev-signer/keys/pub.key"))
        .expect("failed to read dev-signer's checked-in public key");
    assert_eq!(
        public_key_bytes, &expected_public_key,
        "public key read over PKCS#11 doesn't match dev-signer's checked-in key"
    );

    
    let verifying_key = VerifyingKey::<Sha2_192f>::try_from(public_key_bytes.as_slice())
        .expect("invalid public key encoding");
    let signature = Signature::<Sha2_192f>::try_from(signature_bytes.as_slice())
        .expect("invalid signature encoding");
    verifying_key
        .verify(message, &signature)
        .expect("signature produced over PKCS#11 failed independent verification");
}
