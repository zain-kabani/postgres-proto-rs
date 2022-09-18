use bytes::{BufMut, BytesMut};
use log::trace;
use std::mem;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::errors::Error;
use crate::messages::{backend::*, frontend::*};

pub async fn read_startup<S>(stream: &mut S) -> Result<StartupMessageType, Error>
where
    S: tokio::io::AsyncRead + std::marker::Unpin,
{
    let len = match stream.read_i32().await {
        Ok(len) => len,
        Err(_) => return Err(Error::SocketIOError),
    };

    let code = match stream.read_i32().await {
        Ok(len) => len,
        Err(_) => return Err(Error::SocketIOError),
    };

    let mut message_bytes = vec![0u8; len as usize - 8];
    match stream.read_exact(&mut message_bytes).await {
        Ok(_) => {}
        Err(_) => return Err(Error::SocketIOError),
    }

    let mut bytes_mut = BytesMut::with_capacity(len as usize + mem::size_of::<i32>());

    bytes_mut.put_i32(len);
    bytes_mut.put_i32(code);
    bytes_mut.put_slice(&message_bytes);

    trace!(
        "F: Startup message: {:?}",
        String::from_utf8_lossy(&bytes_mut)
    );

    StartupMessageType::new_from_bytes(code, bytes_mut)
}

pub async fn send_startup_message<S>(
    stream: &mut S,
    message: &StartupMessageType,
) -> Result<(), Error>
where
    S: tokio::io::AsyncWrite + std::marker::Unpin,
{
    match stream.write(message.get_bytes()).await {
        Ok(_) => Ok(()),
        Err(_) => return Err(Error::SocketIOError),
    }
}

pub async fn read_frontend_message<S>(stream: &mut S) -> Result<FrontendMessageType, Error>
where
    S: tokio::io::AsyncRead + std::marker::Unpin,
{
    let (msg_type, message_bytes) = read_message_bytes(stream).await?;

    trace!(
        "F: Code: {}\n Message: {:?}",
        msg_type as char,
        String::from_utf8_lossy(&message_bytes)
    );
    FrontendMessageType::new_from_bytes(msg_type, message_bytes)
}

pub async fn send_frontend_message<S>(
    stream: &mut S,
    message: &FrontendMessageType,
) -> Result<(), Error>
where
    S: tokio::io::AsyncWrite + std::marker::Unpin,
{
    match stream.write(message.get_bytes()).await {
        Ok(_) => Ok(()),
        Err(_) => return Err(Error::SocketIOError),
    }
}

pub async fn read_backend_message<S>(stream: &mut S) -> Result<BackendMessageType, Error>
where
    S: tokio::io::AsyncRead + std::marker::Unpin,
{
    let (msg_type, message_bytes) = read_message_bytes(stream).await?;

    trace!(
        "B: Code: {}\n Message: {:?}",
        msg_type as char,
        String::from_utf8_lossy(&message_bytes)
    );

    BackendMessageType::new_from_bytes(msg_type, message_bytes)
}

pub async fn send_backend_message<S>(
    stream: &mut S,
    message: &BackendMessageType,
) -> Result<(), Error>
where
    S: tokio::io::AsyncWrite + std::marker::Unpin,
{
    match stream.write(message.get_bytes()).await {
        Ok(_) => Ok(()),
        Err(_) => return Err(Error::SocketIOError),
    }
}

pub async fn read_message_bytes<S>(stream: &mut S) -> Result<(u8, BytesMut), Error>
where
    S: tokio::io::AsyncRead + std::marker::Unpin,
{
    let msg_type = match stream.read_u8().await {
        Ok(msg_type) => msg_type,
        Err(_) => return Err(Error::SocketIOError),
    };

    let len = match stream.read_i32().await {
        Ok(len) => len,
        Err(_) => return Err(Error::SocketIOError),
    };

    let mut message_body = vec![0u8; len as usize - 4];
    match stream.read_exact(&mut message_body).await {
        Ok(_) => {}
        Err(_) => return Err(Error::SocketIOError),
    }

    let mut message_bytes = BytesMut::with_capacity(mem::size_of::<u8>() + len as usize);

    message_bytes.put_u8(msg_type);
    message_bytes.put_i32(len);
    message_bytes.put_slice(&message_body);

    Ok((msg_type, message_bytes))
}
