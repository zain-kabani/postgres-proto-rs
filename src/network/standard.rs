use std::mem;

use crate::errors::Error;
use crate::messages::{backend::*, frontend::*};

use bytes::{BufMut, BytesMut};

pub fn read_startup<S>(stream: &mut S) -> Result<StartupMessageType, Error>
where
    S: std::io::Read + std::marker::Unpin,
{
    let mut buf = [0; 4];
    match stream.read_exact(&mut buf) {
        Ok(_) => {}
        Err(_) => return Err(Error::SocketIOError),
    }
    let len = i32::from_be_bytes(buf);

    let mut buf = [0; 4];
    match stream.read_exact(&mut buf) {
        Ok(_) => {}
        Err(_) => return Err(Error::SocketIOError),
    }
    let code = i32::from_be_bytes(buf);

    let mut message_bytes = vec![0u8; len as usize - 8];
    match stream.read_exact(&mut message_bytes) {
        Ok(_) => {}
        Err(_) => return Err(Error::SocketIOError),
    }

    let mut bytes_mut = BytesMut::with_capacity(len as usize + mem::size_of::<i32>());

    bytes_mut.put_i32(len);

    bytes_mut.put_i32(code);

    bytes_mut.put_slice(&message_bytes);

    println!(
        "F: Startup message: {:?}",
        String::from_utf8_lossy(&bytes_mut)
    );

    StartupMessageType::new_from_bytes(code, bytes_mut)
}

pub fn send_startup_message<S>(
    stream: &mut S,
    message: &StartupMessageType,
) -> Result<(), std::io::Error>
where
    S: std::io::Write + std::marker::Unpin,
{
    match stream.write(&message.get_bytes()) {
        Ok(_) => Ok(()),
        Err(err) => return Err(err),
    }
}

pub fn read_frontend_message<S>(stream: &mut S) -> Result<FrontendMessageType, Error>
where
    S: std::io::Read + std::marker::Unpin,
{
    let (msg_type, message_bytes) = read_message_bytes(stream)?;

    println!(
        "F: Code: {}\n Message: {:?}",
        msg_type as char,
        String::from_utf8_lossy(&message_bytes)
    );
    FrontendMessageType::new_from_bytes(msg_type, message_bytes)
}

pub fn send_frontend_message<S>(
    stream: &mut S,
    message: &FrontendMessageType,
) -> Result<(), std::io::Error>
where
    S: std::io::Write + std::marker::Unpin,
{
    match stream.write(&message.get_bytes()) {
        Ok(_) => Ok(()),
        Err(err) => return Err(err),
    }
}

pub fn read_backend_message<S>(stream: &mut S) -> Result<BackendMessageType, Error>
where
    S: std::io::Read + std::marker::Unpin,
{
    let (msg_type, message_bytes) = read_message_bytes(stream)?;

    println!(
        "B: Code: {}\n Message: {:?}",
        msg_type as char,
        String::from_utf8_lossy(&message_bytes)
    );

    BackendMessageType::new_from_bytes(msg_type, message_bytes)
}

pub fn send_backend_message<S>(
    stream: &mut S,
    message: &BackendMessageType,
) -> Result<(), std::io::Error>
where
    S: std::io::Write + std::marker::Unpin,
{
    match stream.write(&message.get_bytes()) {
        Ok(_) => Ok(()),
        Err(err) => Err(err),
    }
}

pub fn read_message_bytes<S>(stream: &mut S) -> Result<(u8, BytesMut), Error>
where
    S: std::io::Read + std::marker::Unpin,
{
    let mut buf = [0; 1];
    match stream.read_exact(&mut buf) {
        Ok(_) => {}
        Err(_) => return Err(Error::SocketIOError),
    }
    let msg_type = u8::from_be_bytes(buf);

    let mut buf = [0; 4];
    match stream.read_exact(&mut buf) {
        Ok(_) => {}
        Err(_) => return Err(Error::SocketIOError),
    }
    let len = i32::from_be_bytes(buf);

    let mut message_body = vec![0u8; len as usize - 4];
    match stream.read_exact(&mut message_body) {
        Ok(_) => {}
        Err(_) => return Err(Error::SocketIOError),
    }

    let mut message_bytes = BytesMut::with_capacity(mem::size_of::<u8>() + len as usize);

    message_bytes.put_u8(msg_type);
    message_bytes.put_i32(len);
    message_bytes.put_slice(&message_body);

    Ok((msg_type, message_bytes))
}
