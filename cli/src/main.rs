use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program} keygen <secret-key-path> [--param 128s|128f|192s|192f|256s|256f] [--pub-key <public-key-path>]");
    eprintln!("  {program} sign <secret-key-path> <message> <signature-path> [--param 128s|128f|192s|192f|256s|256f]");
    eprintln!("  {program} verify <public-key-path> <message> <signature-path> [--param 128s|128f|192s|192f|256s|256f]");
    eprintln!("  (--param defaults to 128s for keygen, 128f for sign/verify, matching this project's original desktop workflow)");
}

fn parse_flag_pairs(args: &mut env::Args) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::new();
    while let Some(flag) = args.next() {
        let Some(value) = args.next() else {
            return Err(format!("{flag} requires a value"));
        };
        pairs.push((flag, value));
    }
    Ok(pairs)
}


fn parse_param(name: &str) -> Result<cli::ParamSet, String> {
    cli::ParamSet::parse(name).ok_or_else(|| {
        format!(
            "unknown parameter set '{name}' (expected one of: 128s, 128f, 192s, 192f, 256s, 256f)"
        )
    })
}

fn main() -> ExitCode {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "cli".to_string());

    let Some(command) = args.next() else {
        print_usage(&program);
        return ExitCode::FAILURE;
    };

    match command.as_str() {
        "keygen" => {
            let Some(key_path) = args.next() else {
                print_usage(&program);
                return ExitCode::FAILURE;
            };

            let flags = match parse_flag_pairs(&mut args) {
                Ok(flags) => flags,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };

            let mut param_set = cli::ParamSet::DEFAULT;
            let mut public_key_path: Option<PathBuf> = None;

            for (flag, value) in flags {
                match flag.as_str() {
                    "--param" => match parse_param(&value) {
                        Ok(parsed) => param_set = parsed,
                        Err(e) => {
                            eprintln!("error: {e}");
                            return ExitCode::FAILURE;
                        }
                    },
                    "--pub-key" => public_key_path = Some(PathBuf::from(value)),
                    other => {
                        eprintln!("error: unrecognized argument '{other}'");
                        print_usage(&program);
                        return ExitCode::FAILURE;
                    }
                }
            }

            match cli::generate_keypair(param_set, &PathBuf::from(&key_path), public_key_path.as_deref()) {
                Ok(public_key) => {
                    println!("secret key written to {key_path}");
                    if let Some(public_key_path) = &public_key_path {
                        println!("public key written to {}", public_key_path.display());
                    }
                    println!("public key (hex): {}", hex_encode(&public_key));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: failed to generate keypair: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "sign" => {
            let (Some(key_path), Some(message), Some(signature_path)) =
                (args.next(), args.next(), args.next())
            else {
                print_usage(&program);
                return ExitCode::FAILURE;
            };

            // Defaults to 128f
            let mut param_set = cli::ParamSet::Sha2_128f;
            let flags = match parse_flag_pairs(&mut args) {
                Ok(flags) => flags,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            for (flag, value) in flags {
                match flag.as_str() {
                    "--param" => match parse_param(&value) {
                        Ok(parsed) => param_set = parsed,
                        Err(e) => {
                            eprintln!("error: {e}");
                            return ExitCode::FAILURE;
                        }
                    },
                    other => {
                        eprintln!("error: unrecognized argument '{other}'");
                        print_usage(&program);
                        return ExitCode::FAILURE;
                    }
                }
            }

            match cli::sign_message(
                param_set,
                message.as_bytes(),
                &PathBuf::from(&key_path),
                &PathBuf::from(&signature_path),
            ) {
                Ok(signature) => {
                    println!("signature written to {signature_path}");
                    println!("signature (hex): {}", hex_encode(&signature));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: failed to sign message: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "verify" => {
            let (Some(public_key_path), Some(message), Some(signature_path)) =
                (args.next(), args.next(), args.next())
            else {
                print_usage(&program);
                return ExitCode::FAILURE;
            };

            // Same default rationale as `sign`: 128f, not ParamSet::DEFAULT.
            let mut param_set = cli::ParamSet::Sha2_128f;
            let flags = match parse_flag_pairs(&mut args) {
                Ok(flags) => flags,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            for (flag, value) in flags {
                match flag.as_str() {
                    "--param" => match parse_param(&value) {
                        Ok(parsed) => param_set = parsed,
                        Err(e) => {
                            eprintln!("error: {e}");
                            return ExitCode::FAILURE;
                        }
                    },
                    other => {
                        eprintln!("error: unrecognized argument '{other}'");
                        print_usage(&program);
                        return ExitCode::FAILURE;
                    }
                }
            }

            match cli::verify_message(
                param_set,
                message.as_bytes(),
                &PathBuf::from(&signature_path),
                &PathBuf::from(&public_key_path),
            ) {
                Ok(true) => {
                    println!("valid");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    println!("invalid");
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("error: failed to verify signature: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            print_usage(&program);
            ExitCode::FAILURE
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
