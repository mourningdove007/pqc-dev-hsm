#![cfg_attr(not(any(test, feature = "std")), no_std)]

pub const PROTOCOL_VERSION: u8 = 1;

pub const FIXED_OBJECT_HANDLE: u32 = 1;

pub const HEADER_LEN: usize = 5;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    GetInfo = 1,
    ListObjects = 2,
    GetPublicKey = 3,
    Sign = 4,
    GenerateKeypair = 5,
    DeleteObject = 6,
}

impl TryFrom<u8> for Command {
    type Error = ();

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            1 => Ok(Command::GetInfo),
            2 => Ok(Command::ListObjects),
            3 => Ok(Command::GetPublicKey),
            4 => Ok(Command::Sign),
            5 => Ok(Command::GenerateKeypair),
            6 => Ok(Command::DeleteObject),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    UnknownCommand = 1,
    BadRequest = 2,
    NotFound = 3,
    SigningFailed = 4,
    NotImplemented = 5,
    BufferTooSmall = 6,
}

impl From<Status> for u8 {
    fn from(status: Status) -> u8 {
        status as u8
    }
}

pub trait SigningBackend {
    fn param_set_name(&self) -> &str;
    fn public_key(&self) -> &[u8];
    fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, ()>;
    fn generate_keypair(&mut self) -> bool;
}

fn read_handle(payload: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = payload.get(0..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}


pub fn dispatch(
    command_byte: u8,
    request_payload: &[u8],
    backend: &mut impl SigningBackend,
    response_buf: &mut [u8],
) -> (Status, usize) {
    let Ok(command) = Command::try_from(command_byte) else {
        return (Status::UnknownCommand, 0);
    };

    match command {
        Command::GetInfo => {
            let name = backend.param_set_name().as_bytes();
            if response_buf.len() < 2 + name.len() || name.len() > u8::MAX as usize {
                return (Status::BufferTooSmall, 0);
            }
            response_buf[0] = PROTOCOL_VERSION;
            response_buf[1] = name.len() as u8;
            response_buf[2..2 + name.len()].copy_from_slice(name);
            (Status::Ok, 2 + name.len())
        }

        Command::ListObjects => {
            if response_buf.len() < 5 {
                return (Status::BufferTooSmall, 0);
            }
            response_buf[0] = 1;
            response_buf[1..5].copy_from_slice(&FIXED_OBJECT_HANDLE.to_le_bytes());
            (Status::Ok, 5)
        }

        Command::GetPublicKey => {
            let Some(handle) = read_handle(request_payload) else {
                return (Status::BadRequest, 0);
            };
            if handle != FIXED_OBJECT_HANDLE {
                return (Status::NotFound, 0);
            }
            let pk = backend.public_key();
            if response_buf.len() < pk.len() {
                return (Status::BufferTooSmall, 0);
            }
            response_buf[..pk.len()].copy_from_slice(pk);
            (Status::Ok, pk.len())
        }

        Command::Sign => {
            let Some(handle) = read_handle(request_payload) else {
                return (Status::BadRequest, 0);
            };
            if handle != FIXED_OBJECT_HANDLE {
                return (Status::NotFound, 0);
            }
            let message = &request_payload[4..];
            match backend.sign(message, response_buf) {
                Ok(written) => (Status::Ok, written),
                Err(()) => (Status::SigningFailed, 0),
            }
        }

        Command::GenerateKeypair => {
            
            if !backend.generate_keypair() {
                return (Status::NotImplemented, 0);
            }
            let pk = backend.public_key();
            if response_buf.len() < pk.len() {
                return (Status::BufferTooSmall, 0);
            }
            response_buf[..pk.len()].copy_from_slice(pk);
            (Status::Ok, pk.len())
        }

        Command::DeleteObject => (Status::NotImplemented, 0),
    }
}

pub trait Read {
    type Error;
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}

pub trait Write {
    type Error;
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
}

#[cfg(any(test, feature = "std"))]
impl<T: std::io::Read> Read for T {
    type Error = std::io::Error;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        std::io::Read::read_exact(self, buf)
    }
}

#[cfg(any(test, feature = "std"))]
impl<T: std::io::Write> Write for T {
    type Error = std::io::Error;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        std::io::Write::write_all(self, buf)
    }
}

pub fn write_frame<W: Write>(w: &mut W, kind: u8, payload: &[u8]) -> Result<(), W::Error> {
    let len = (1 + payload.len()) as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&[kind])?;
    w.write_all(payload)?;
    Ok(())
}

#[derive(Debug)]
pub enum ReadFrameError<E> {
    Io(E),
    FrameTooLarge { declared: u32, max: usize },
}

pub fn read_frame<'buf, R: Read>(
    r: &mut R,
    buf: &'buf mut [u8],
) -> Result<(u8, &'buf [u8]), ReadFrameError<R::Error>> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes).map_err(ReadFrameError::Io)?;
    let len = u32::from_le_bytes(len_bytes);

    if len == 0 || len as usize > buf.len() {
        let mut remaining = len as usize;
        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            if r.read_exact(&mut buf[..chunk]).is_err() {
                break;
            }
            remaining -= chunk;
        }
        return Err(ReadFrameError::FrameTooLarge {
            declared: len,
            max: buf.len(),
        });
    }

    let len = len as usize;
    r.read_exact(&mut buf[..len]).map_err(ReadFrameError::Io)?;
    Ok((buf[0], &buf[1..len]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct MockBackend {
        param_set_name: &'static str,
        public_key: Vec<u8>,
        fail_signing: bool,
        supports_keygen: bool,
    }

    impl SigningBackend for MockBackend {
        fn param_set_name(&self) -> &str {
            self.param_set_name
        }

        fn public_key(&self) -> &[u8] {
            &self.public_key
        }

        fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, ()> {
            if self.fail_signing {
                return Err(());
            }
            
            let mut reversed = message.to_vec();
            reversed.reverse();
            if out.len() < reversed.len() {
                return Err(());
            }
            out[..reversed.len()].copy_from_slice(&reversed);
            Ok(reversed.len())
        }

        fn generate_keypair(&mut self) -> bool {
            if !self.supports_keygen {
                return false;
            }
            self.public_key = vec![0xAB; self.public_key.len()];
            true
        }
    }

    fn backend() -> MockBackend {
        MockBackend {
            param_set_name: "192f",
            public_key: vec![1, 2, 3, 4],
            fail_signing: false,
            supports_keygen: true,
        }
    }

    #[test]
    fn get_info_reports_param_set_name() {
        let mut backend = backend();
        let mut out = [0u8; 64];
        let (status, len) = dispatch(Command::GetInfo as u8, &[], &mut backend, &mut out);
        assert_eq!(status, Status::Ok);
        assert_eq!(out[0], PROTOCOL_VERSION);
        assert_eq!(out[1] as usize, "192f".len());
        assert_eq!(&out[2..len], b"192f");
    }

    #[test]
    fn list_objects_reports_the_one_fixed_handle() {
        let mut backend = backend();
        let mut out = [0u8; 64];
        let (status, len) = dispatch(Command::ListObjects as u8, &[], &mut backend, &mut out);
        assert_eq!(status, Status::Ok);
        assert_eq!(out[0], 1);
        assert_eq!(&out[1..len], FIXED_OBJECT_HANDLE.to_le_bytes());
    }

    #[test]
    fn get_public_key_returns_the_key_for_the_fixed_handle() {
        let mut backend = backend();
        let mut out = [0u8; 64];
        let request = FIXED_OBJECT_HANDLE.to_le_bytes();
        let (status, len) = dispatch(Command::GetPublicKey as u8, &request, &mut backend, &mut out);
        assert_eq!(status, Status::Ok);
        assert_eq!(&out[..len], backend.public_key());
    }

    #[test]
    fn get_public_key_rejects_unknown_handle() {
        let mut backend = backend();
        let mut out = [0u8; 64];
        let request = 999u32.to_le_bytes();
        let (status, _) = dispatch(Command::GetPublicKey as u8, &request, &mut backend, &mut out);
        assert_eq!(status, Status::NotFound);
    }

    #[test]
    fn sign_round_trips_through_the_backend() {
        let mut backend = backend();
        let mut out = [0u8; 64];
        let mut request = FIXED_OBJECT_HANDLE.to_le_bytes().to_vec();
        request.extend_from_slice(b"hello");
        let (status, len) = dispatch(Command::Sign as u8, &request, &mut backend, &mut out);
        assert_eq!(status, Status::Ok);
        assert_eq!(&out[..len], b"olleh");
    }

    #[test]
    fn sign_reports_backend_failure() {
        let mut backend = backend();
        backend.fail_signing = true;
        let mut out = [0u8; 64];
        let mut request = FIXED_OBJECT_HANDLE.to_le_bytes().to_vec();
        request.extend_from_slice(b"hello");
        let (status, _) = dispatch(Command::Sign as u8, &request, &mut backend, &mut out);
        assert_eq!(status, Status::SigningFailed);
    }

    #[test]
    fn generate_keypair_never_returns_private_key_bytes() {
        let mut backend = backend();
        let mut out = [0u8; 64];
        let (status, len) =
            dispatch(Command::GenerateKeypair as u8, &[], &mut backend, &mut out);
        assert_eq!(status, Status::Ok);
        // The response is exactly the new public key, nothing else.
        assert_eq!(len, backend.public_key().len());
        assert_eq!(&out[..len], backend.public_key());
    }

    #[test]
    fn generate_keypair_not_implemented_when_backend_declines() {
        let mut backend = backend();
        backend.supports_keygen = false;
        let mut out = [0u8; 64];
        let (status, _) =
            dispatch(Command::GenerateKeypair as u8, &[], &mut backend, &mut out);
        assert_eq!(status, Status::NotImplemented);
    }

    #[test]
    fn delete_object_is_not_implemented() {
        let mut backend = backend();
        let mut out = [0u8; 64];
        let request = FIXED_OBJECT_HANDLE.to_le_bytes();
        let (status, _) = dispatch(Command::DeleteObject as u8, &request, &mut backend, &mut out);
        assert_eq!(status, Status::NotImplemented);
    }

    #[test]
    fn unknown_command_byte_is_rejected() {
        let mut backend = backend();
        let mut out = [0u8; 64];
        let (status, _) = dispatch(0xFF, &[], &mut backend, &mut out);
        assert_eq!(status, Status::UnknownCommand);
    }

    #[test]
    fn frame_round_trips_over_a_byte_stream() {
        let mut stream = Cursor::new(Vec::new());
        write_frame(&mut stream, Command::Sign as u8, b"payload").unwrap();

        stream.set_position(0);
        let mut buf = [0u8; 64];
        let (kind, payload) = read_frame(&mut stream, &mut buf).unwrap();
        assert_eq!(kind, Command::Sign as u8);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn read_frame_rejects_a_frame_larger_than_the_buffer() {
        let mut stream = Cursor::new(Vec::new());
        write_frame(&mut stream, Command::Sign as u8, &[0u8; 100]).unwrap();

        stream.set_position(0);
        let mut buf = [0u8; 16];
        let err = read_frame(&mut stream, &mut buf).unwrap_err();
        assert!(matches!(err, ReadFrameError::FrameTooLarge { .. }));
    }

    #[test]
    fn read_frame_resyncs_after_an_oversized_frame() {
        let mut stream = Cursor::new(Vec::new());
        write_frame(&mut stream, Command::Sign as u8, &[0u8; 100]).unwrap();
        write_frame(&mut stream, Command::GetInfo as u8, b"ok").unwrap();

        stream.set_position(0);
        let mut buf = [0u8; 16];
        assert!(matches!(
            read_frame(&mut stream, &mut buf),
            Err(ReadFrameError::FrameTooLarge { .. })
        ));

        let (kind, payload) = read_frame(&mut stream, &mut buf).unwrap();
        assert_eq!(kind, Command::GetInfo as u8);
        assert_eq!(payload, b"ok");
    }
}
