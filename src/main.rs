use std::{collections::HashMap, mem};

use num_traits::FromPrimitive;

use bytes::{BufMut, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener,
    },
};

mod errors;
mod messages;

use errors::Error;
use messages::*;

#[tokio::main()]
async fn main() {
    println!("HELLO");

    let addr = format!("{}:{}", "localhost", "6432");

    let listener = match TcpListener::bind(&addr).await {
        Ok(sock) => sock,
        Err(err) => {
            println!("Listener socket error: {:?}", err);
            return;
        }
    };

    let startup_thing = StartupParameters::new(
        123,
        HashMap::from([
            (String::from("hello"), String::from("world")),
            (String::from("users"), String::from("bob")),
        ]),
    );

    println!("{:?}", startup_thing.get_type());

    match startup_thing.get_type() {
        StartupMessageType::StartupParameters => println!("IT WORKED"),
        _ => println!("DIDN'T WORK"),
    }

    loop {
        let (socket, _) = listener.accept().await.unwrap();

        let (mut read_stream, mut write_stream) = socket.into_split();

        let res = read_startup(&mut read_stream).await.unwrap();

        match res.get_type() {
            StartupMessageType::StartupParameters => {
                println!("Got startup parameters");

                let startup_params = res.as_any().downcast_ref::<StartupParameters>().unwrap();
                println!("params {:?}", startup_params.parameters);
            }
            _ => {
                println!("Didn't get startup parameters");
            }
        }

        send_authentication_message(&mut write_stream, AuthenticationOk::new()).await;

        send_backend_message(&mut write_stream, ReadyForQuery::new(b'Z')).await;

        let res = read_frontend_message(read_stream).await.unwrap();

        match res.get_type() {
            FrontendMessageType::Query => {
                let query = res.as_any().downcast_ref::<Query>().unwrap();
                println!("Got query {:?}", query.query_string);
            }
        }
    }
}

async fn read_startup(
    stream: &mut OwnedReadHalf,
) -> Result<Box<dyn Message<MessageType = StartupMessageType>>, Error> {
    let len = match stream.read_i32().await {
        Ok(len) => len,
        Err(_) => return Err(Error::SocketIOError),
    };

    let code = match stream.read_i32().await {
        Ok(len) => len,
        Err(_) => return Err(Error::SocketIOError),
    };

    println!("code {}", code);

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

async fn read_frontend_message(
    mut stream: OwnedReadHalf,
) -> Result<Box<dyn Message<MessageType = FrontendMessageType>>, Error> {
    let code = match stream.read_u8().await {
        Ok(len) => len,
        Err(_) => return Err(Error::SocketIOError),
    };

    let len = match stream.read_i32().await {
        Ok(len) => len,
        Err(_) => return Err(Error::SocketIOError),
    };

    let mut message_bytes = vec![0u8; len as usize - 4];
    match stream.read_exact(&mut message_bytes).await {
        Ok(_) => {}
        Err(_) => return Err(Error::SocketIOError),
    }

    let mut bytes_mut = BytesMut::with_capacity(mem::size_of::<u8>() + len as usize);

    bytes_mut.put_u8(code);
    bytes_mut.put_i32(len);
    bytes_mut.put_slice(&message_bytes);

    println!(
        "F: {} {:?}",
        code as char,
        String::from_utf8_lossy(&message_bytes)
    );
    match code as char {
        'Q' => {
            let query = Query::new_from_bytes(bytes_mut)?;
            Ok(Box::new(query))
        }
        _ => panic!("unknown protocol"),
    }
}

async fn send_authentication_message(
    stream: &mut OwnedWriteHalf,
    message: impl Message + AuthenticationMessage,
) {
    stream.write(&message.get_bytes()).await.unwrap();
}

async fn send_backend_message(stream: &mut OwnedWriteHalf, message: impl Message + BackendMessage) {
    stream.write(&message.get_bytes()).await.unwrap();
}
