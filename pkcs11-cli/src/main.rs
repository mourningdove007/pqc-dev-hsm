use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program} get-pubkey --module <path> --id <hex> --output <path>");
    eprintln!("  {program} generate-keypair --module <path> [--output <path>]");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_flag_pairs(mut args: env::Args) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::new();
    while let Some(flag) = args.next() {
        let Some(value) = args.next() else {
            return Err(format!("{flag} requires a value"));
        };
        pairs.push((flag, value));
    }
    Ok(pairs)
}

fn parse_hex_id(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!(
            "--id must have an even number of hex digits, got '{s}'"
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("invalid hex in --id: {e}"))
        })
        .collect()
}

fn get_pubkey(module: &PathBuf, id: &[u8], output: &PathBuf) -> Result<usize, String> {
    let pkcs11 = Pkcs11::new(module).map_err(|e| format!("failed to load module: {e}"))?;
    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .map_err(|e| format!("C_Initialize failed: {e}"))?;

    let slot = *pkcs11
        .get_slots_with_token()
        .map_err(|e| format!("C_GetSlotList failed: {e}"))?
        .first()
        .ok_or_else(|| "no slot with a token present".to_string())?;

    let session = pkcs11
        .open_ro_session(slot)
        .map_err(|e| format!("C_OpenSession failed: {e}"))?;

    let objects = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Id(id.to_vec()),
        ])
        .map_err(|e| format!("C_FindObjects failed: {e}"))?;

    let handle = *objects
        .first()
        .ok_or_else(|| "no public key object matches the given --id".to_string())?;

    let attrs = session
        .get_attributes(handle, &[AttributeType::Value])
        .map_err(|e| format!("C_GetAttributeValue failed: {e}"))?;

    let Some(Attribute::Value(bytes)) = attrs.into_iter().next() else {
        return Err("expected a CKA_VALUE attribute back".to_string());
    };

    std::fs::write(output, &bytes)
        .map_err(|e| format!("failed to write {}: {e}", output.display()))?;

    Ok(bytes.len())
}

fn generate_keypair(module: &PathBuf, output: Option<&PathBuf>) -> Result<Vec<u8>, String> {
    let pkcs11 = Pkcs11::new(module).map_err(|e| format!("failed to load module: {e}"))?;
    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .map_err(|e| format!("C_Initialize failed: {e}"))?;

    let slot = *pkcs11
        .get_slots_with_token()
        .map_err(|e| format!("C_GetSlotList failed: {e}"))?
        .first()
        .ok_or_else(|| "no slot with a token present".to_string())?;

    let session = pkcs11
        .open_rw_session(slot)
        .map_err(|e| format!("C_OpenSession failed: {e}"))?;

    let mechanism_type =
        MechanismType::new_vendor_defined(pkcs11_provider::CKM_SLH_DSA_SHA2_VENDOR)
            .map_err(|e| format!("mechanism type construction failed: {e}"))?;
    let mechanism = Mechanism::VendorDefined(VendorDefinedMechanism::new::<()>(mechanism_type, None));

    let (public_key, _private_key) = session
        .generate_key_pair(&mechanism, &[], &[])
        .map_err(|e| format!("C_GenerateKeyPair failed: {e}"))?;

    let attrs = session
        .get_attributes(public_key, &[AttributeType::Value])
        .map_err(|e| format!("C_GetAttributeValue failed: {e}"))?;

    let Some(Attribute::Value(bytes)) = attrs.into_iter().next() else {
        return Err("expected a CKA_VALUE attribute back".to_string());
    };

    if let Some(output) = output {
        std::fs::write(output, &bytes)
            .map_err(|e| format!("failed to write {}: {e}", output.display()))?;
    }

    Ok(bytes)
}

fn main() -> ExitCode {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "pkcs11-cli".to_string());

    let Some(command) = args.next() else {
        print_usage(&program);
        return ExitCode::FAILURE;
    };

    if command != "get-pubkey" && command != "generate-keypair" {
        eprintln!("error: unknown command '{command}'");
        print_usage(&program);
        return ExitCode::FAILURE;
    }

    let flags = match parse_flag_pairs(args) {
        Ok(flags) => flags,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut module: Option<PathBuf> = None;
    let mut id: Option<Vec<u8>> = None;
    let mut output: Option<PathBuf> = None;

    for (flag, value) in flags {
        match flag.as_str() {
            "--module" => module = Some(PathBuf::from(value)),
            "--id" => match parse_hex_id(&value) {
                Ok(bytes) => id = Some(bytes),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            },
            "--output" => output = Some(PathBuf::from(value)),
            other => {
                eprintln!("error: unknown flag '{other}'");
                print_usage(&program);
                return ExitCode::FAILURE;
            }
        }
    }

    let Some(module) = module else {
        eprintln!("error: --module is required");
        print_usage(&program);
        return ExitCode::FAILURE;
    };

    if command == "get-pubkey" {
        let (Some(id), Some(output)) = (id, output) else {
            eprintln!("error: get-pubkey requires --id and --output");
            print_usage(&program);
            return ExitCode::FAILURE;
        };

        return match get_pubkey(&module, &id, &output) {
            Ok(len) => {
                println!("wrote {len} bytes to {}", output.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        };
    }

    match generate_keypair(&module, output.as_ref()) {
        Ok(public_key) => {
            println!("new public key: {}", hex_encode(&public_key));
            if let Some(output) = &output {
                println!("wrote {} bytes to {}", public_key.len(), output.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
