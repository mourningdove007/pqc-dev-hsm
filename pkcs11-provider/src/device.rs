
use std::io;
use std::net::TcpStream;
use std::time::Duration;

use serialport::SerialPort;
use token_core::Command;


pub enum Connection {
    Tcp(TcpStream),
    Serial(Box<dyn SerialPort>),
}

impl io::Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Connection::Tcp(s) => s.read(buf),
            Connection::Serial(s) => s.read(buf),
        }
    }
}

impl io::Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Connection::Tcp(s) => s.write(buf),
            Connection::Serial(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Connection::Tcp(s) => s.flush(),
            Connection::Serial(s) => s.flush(),
        }
    }
}

/// Parses `tcp://host:port` or `serial:/path/to/port:baud` and connects.
pub fn connect(endpoint: &str) -> Result<Connection, String> {
    if let Some(rest) = endpoint.strip_prefix("tcp://") {
        let stream =
            TcpStream::connect(rest).map_err(|e| format!("tcp connect to {rest} failed: {e}"))?;
        let _ = stream.set_nodelay(true);
        Ok(Connection::Tcp(stream))
    } else if let Some(rest) = endpoint.strip_prefix("serial:") {
        let (path, baud) = rest.rsplit_once(':').ok_or_else(|| {
            format!("serial endpoint must be 'serial:<path>:<baud>', got '{rest}'")
        })?;
        let baud: u32 = baud
            .parse()
            .map_err(|_| format!("invalid baud rate '{baud}'"))?;
        let port = serialport::new(path, baud)
            .timeout(Duration::from_secs(5))
            .open()
            .map_err(|e| format!("failed to open serial port {path}: {e}"))?;
        Ok(Connection::Serial(port))
    } else {
        Err(format!(
            "PQC_HSM_ENDPOINT must start with 'tcp://' or 'serial:', got '{endpoint}'"
        ))
    }
}


const RESPONSE_BUF_LEN: usize = 65536;

pub struct DeviceConnection {
    connection: Connection,
}

impl DeviceConnection {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    fn request(&mut self, command: Command, payload: &[u8]) -> Result<(u8, Vec<u8>), String> {
        token_core::write_frame(&mut self.connection, command as u8, payload)
            .map_err(|e| format!("write failed: {e}"))?;
        let mut buf = vec![0u8; RESPONSE_BUF_LEN];
        let (status, response) = token_core::read_frame(&mut self.connection, &mut buf)
            .map_err(|e| format!("read failed: {e:?}"))?;
        Ok((status, response.to_vec()))
    }

    pub fn get_info(&mut self) -> Result<String, String> {
        let (status, payload) = self.request(Command::GetInfo, &[])?;
        if status != token_core::Status::Ok as u8 {
            return Err(format!("GET_INFO failed with status {status}"));
        }
        let name_len = *payload.get(1).ok_or("GET_INFO response too short")? as usize;
        let name_bytes = payload
            .get(2..2 + name_len)
            .ok_or("GET_INFO response truncated")?;
        String::from_utf8(name_bytes.to_vec()).map_err(|e| e.to_string())
    }

    pub fn get_public_key(&mut self, handle: u32) -> Result<Vec<u8>, String> {
        let (status, payload) = self.request(Command::GetPublicKey, &handle.to_le_bytes())?;
        if status != token_core::Status::Ok as u8 {
            return Err(format!("GET_PUBLIC_KEY failed with status {status}"));
        }
        Ok(payload)
    }

    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, String> {
        let mut payload = token_core::FIXED_OBJECT_HANDLE.to_le_bytes().to_vec();
        payload.extend_from_slice(message);
        let (status, response) = self.request(Command::Sign, &payload)?;
        if status != token_core::Status::Ok as u8 {
            return Err(format!("SIGN failed with status {status}"));
        }
        Ok(response)
    }
}
