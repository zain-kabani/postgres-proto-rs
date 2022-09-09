use std::mem;

use crate::messages::{Message, frontend::*, backend::*};
use crate::errors::Error;

use bytes::{BytesMut, BufMut};
use num_traits::FromPrimitive;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};


pub async fn read_startup(
    stream: &mut OwnedReadHalf,
) -> Result<Box<dyn StartupMessage<MessageType = StartupMessageType>>, Error> {
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

    println!("F: {:?}", String::from_utf8_lossy(&bytes_mut));

    match FromPrimitive::from_i32(code) {
        Some(StartupMessageCodes::ProtocolVersion) => {
            let startup_message = StartupParameters::new_from_bytes(bytes_mut)?;
            Ok(Box::new(startup_message))
        }
        Some(StartupMessageCodes::SSLRequest) => {
            let ssl_request = SSLRequest::new_from_bytes(bytes_mut)?;
            Ok(Box::new(ssl_request))
        }
        Some(StartupMessageCodes::CancelRequest) => {
            let cancel_request = CancelRequest::new_from_bytes(bytes_mut)?;
            Ok(Box::new(cancel_request))
        }
        Some(StartupMessageCodes::GssEncReq) => {
            let gss_enc_request = GssEncReq::new_from_bytes(bytes_mut)?;
            Ok(Box::new(gss_enc_request))
        }
        None => {
            panic!("unknown startup code {}", code);
        }
    }
}

pub async fn read_frontend_message(
    stream: &mut OwnedReadHalf,
) -> Result<Box<dyn FrontendMessage<MessageType = FrontendMessageType>>, Error> {

    let (code, message_bytes) = read_message_bytes(stream).await?;

    println!(
        "F: {} {:?}",
        code as char,
        String::from_utf8_lossy(&message_bytes)
    );
    match code as char {
        'Q' => {
            let query = Query::new_from_bytes(message_bytes)?;
            Ok(Box::new(query))
        }
        _ => panic!("unknown protocol"),
    }
}


pub async fn send_backend_message(stream: &mut OwnedWriteHalf, message: impl BackendMessage) {
    stream.write(&message.get_bytes()).await.unwrap();
}

pub async fn read_message_bytes(stream: &mut OwnedReadHalf) -> Result<(u8, BytesMut), Error> {
    let code = match stream.read_u8().await {
        Ok(code) => code,
        Err(_) => return Err(Error::SocketIOError),
    };

    let len = match stream.read_i32().await {
        Ok(len) => len,
        Err(_) => return Err(Error::SocketIOError),
    };

    let mut message_body = vec![0u8; len as usize - 4];
    match stream.read_exact(&mut message_body).await {
        Ok(_) => {},
        Err(_) => return Err(Error::SocketIOError),
    }

    let mut message_bytes = BytesMut::with_capacity(mem::size_of::<u8>() + len as usize);

    message_bytes.put_u8(code);
    message_bytes.put_i32(len);
    message_bytes.put_slice(&message_body);

    Ok((code, message_bytes))
}