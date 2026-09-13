use std::fs;
use std::io;
use std::path::Path;

use rand_core::OsRng;
use signature::{Keypair, Signer, Verifier};
use slh_dsa::{
    ParameterSet, Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Signature,
    SigningKey, VerifyingKey,
};


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamSet {
    Sha2_128s,
    Sha2_128f,
    Sha2_192s,
    Sha2_192f,
    Sha2_256s,
    Sha2_256f,
}

impl ParamSet {
    
    pub const DEFAULT: Self = Self::Sha2_128s;

    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "128s" => Self::Sha2_128s,
            "128f" => Self::Sha2_128f,
            "192s" => Self::Sha2_192s,
            "192f" => Self::Sha2_192f,
            "256s" => Self::Sha2_256s,
            "256f" => Self::Sha2_256f,
            _ => return None,
        })
    }
}

pub fn generate_keypair(
    param_set: ParamSet,
    secret_key_path: &Path,
    public_key_path: Option<&Path>,
) -> io::Result<Vec<u8>> {
    match param_set {
        ParamSet::Sha2_128s => generate_keypair_for::<Sha2_128s>(secret_key_path, public_key_path),
        ParamSet::Sha2_128f => generate_keypair_for::<Sha2_128f>(secret_key_path, public_key_path),
        ParamSet::Sha2_192s => generate_keypair_for::<Sha2_192s>(secret_key_path, public_key_path),
        ParamSet::Sha2_192f => generate_keypair_for::<Sha2_192f>(secret_key_path, public_key_path),
        ParamSet::Sha2_256s => generate_keypair_for::<Sha2_256s>(secret_key_path, public_key_path),
        ParamSet::Sha2_256f => generate_keypair_for::<Sha2_256f>(secret_key_path, public_key_path),
    }
}

fn generate_keypair_for<P: ParameterSet>(
    secret_key_path: &Path,
    public_key_path: Option<&Path>,
) -> io::Result<Vec<u8>> {
    let mut rng = OsRng;
    let signing_key = SigningKey::<P>::new(&mut rng);

    fs::write(secret_key_path, signing_key.to_bytes().as_slice())?;

    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    if let Some(public_key_path) = public_key_path {
        fs::write(public_key_path, &public_key)?;
    }

    Ok(public_key)
}

pub fn sign_message(
    param_set: ParamSet,
    message: &[u8],
    secret_key_path: &Path,
    signature_path: &Path,
) -> io::Result<Vec<u8>> {
    match param_set {
        ParamSet::Sha2_128s => sign_message_for::<Sha2_128s>(message, secret_key_path, signature_path),
        ParamSet::Sha2_128f => sign_message_for::<Sha2_128f>(message, secret_key_path, signature_path),
        ParamSet::Sha2_192s => sign_message_for::<Sha2_192s>(message, secret_key_path, signature_path),
        ParamSet::Sha2_192f => sign_message_for::<Sha2_192f>(message, secret_key_path, signature_path),
        ParamSet::Sha2_256s => sign_message_for::<Sha2_256s>(message, secret_key_path, signature_path),
        ParamSet::Sha2_256f => sign_message_for::<Sha2_256f>(message, secret_key_path, signature_path),
    }
}

fn sign_message_for<P: ParameterSet>(
    message: &[u8],
    secret_key_path: &Path,
    signature_path: &Path,
) -> io::Result<Vec<u8>> {
    let key_bytes = fs::read(secret_key_path)?;
    let signing_key = SigningKey::<P>::try_from(key_bytes.as_slice()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid secret key at {}", secret_key_path.display()),
        )
    })?;

    let signature = signing_key
        .try_sign(message)
        .map_err(|e| io::Error::other(format!("signing failed: {e}")))?;
    let signature_bytes = signature.to_bytes().to_vec();

    fs::write(signature_path, &signature_bytes)?;

    Ok(signature_bytes)
}

pub fn verify_message(
    param_set: ParamSet,
    message: &[u8],
    signature_path: &Path,
    public_key_path: &Path,
) -> io::Result<bool> {
    match param_set {
        ParamSet::Sha2_128s => {
            verify_message_for::<Sha2_128s>(message, signature_path, public_key_path)
        }
        ParamSet::Sha2_128f => {
            verify_message_for::<Sha2_128f>(message, signature_path, public_key_path)
        }
        ParamSet::Sha2_192s => {
            verify_message_for::<Sha2_192s>(message, signature_path, public_key_path)
        }
        ParamSet::Sha2_192f => {
            verify_message_for::<Sha2_192f>(message, signature_path, public_key_path)
        }
        ParamSet::Sha2_256s => {
            verify_message_for::<Sha2_256s>(message, signature_path, public_key_path)
        }
        ParamSet::Sha2_256f => {
            verify_message_for::<Sha2_256f>(message, signature_path, public_key_path)
        }
    }
}

fn verify_message_for<P: ParameterSet>(
    message: &[u8],
    signature_path: &Path,
    public_key_path: &Path,
) -> io::Result<bool> {
    let public_key_bytes = fs::read(public_key_path)?;
    let verifying_key = VerifyingKey::<P>::try_from(public_key_bytes.as_slice()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid public key at {}", public_key_path.display()),
        )
    })?;

    let signature_bytes = fs::read(signature_path)?;
    let signature = Signature::<P>::try_from(signature_bytes.as_slice()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid signature at {}", signature_path.display()),
        )
    })?;

    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[cfg(test)]
mod tests;
