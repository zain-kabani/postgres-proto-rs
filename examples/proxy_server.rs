use std::collections::HashMap;

use postgres_proto_rs::network::tokio::*;

use postgres_proto_rs::messages::{backend::*, frontend::*};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main()]
async fn main() {
    let mut backend = create_backend().await;

    let addr = format!("{}:{}", "localhost", "6432");

    let client_listener = match TcpListener::bind(&addr).await {
        Ok(sock) => sock,
        Err(err) => {
            println!("Listener socket error: {:?}", err);
            return;
        }
    };

    let (socket, _) = client_listener.accept().await.unwrap();

    let mut frontend = create_frontend(socket).await;

    let _startup_message = read_startup(&mut frontend.read_stream).await.unwrap();

    send_backend_message(
        &mut frontend.write_stream,
        &BackendMessageType::AuthenticationOk(AuthenticationOk::new()),
    )
    .await
    .unwrap();

    send_backend_message(
        &mut frontend.write_stream,
        &BackendMessageType::ReadyForQuery(ReadyForQuery::new(b'I')),
    )
    .await
    .unwrap();

    loop {
        let message = read_frontend_message(&mut frontend.read_stream)
            .await
            .unwrap();

        match &message {
            FrontendMessageType::Query(query) => {
                println!("query: {}", query.get_params().query_string);
            }
            _ => {}
        }

        send_frontend_message(&mut backend.write_stream, &message)
            .await
            .unwrap();

        loop {
            let message = read_backend_message(&mut backend.read_stream)
                .await
                .unwrap();

            send_backend_message(&mut frontend.write_stream, &message)
                .await
                .unwrap();

            match message {
                BackendMessageType::ReadyForQuery(ready_for_query) => {
                    println!("tx_status: {}", ready_for_query.get_params().tx_status);
                    break;
                }
                _ => {}
            };
        }
    }
}

pub struct Backend {
    pub read_stream: OwnedReadHalf,
    pub write_stream: OwnedWriteHalf,
}

impl Backend {
    pub fn new(read_stream: OwnedReadHalf, write_stream: OwnedWriteHalf) -> Self {
        Self {
            read_stream,
            write_stream,
        }
    }
}

pub struct Frontend {
    pub read_stream: OwnedReadHalf,
    pub write_stream: OwnedWriteHalf,
}

impl Frontend {
    pub fn new(read_stream: OwnedReadHalf, write_stream: OwnedWriteHalf) -> Self {
        Self {
            read_stream,
            write_stream,
        }
    }
}

async fn create_backend() -> Backend {
    let stream = match TcpStream::connect(&format!("{}:{}", "localhost", 5432)).await {
        Ok(stream) => stream,
        Err(err) => {
            panic!("Could not connect to server: {}", err);
        }
    };

    let (mut read_stream, mut write_stream) = stream.into_split();

    let startup_params = StartupParameters::new(HashMap::from([
        ("user".to_string(), "postgres".to_string()),
        ("database".to_string(), "postgres".to_string()),
        ("client_encoding".to_string(), "UTF8".to_string()),
        ("application_name".to_string(), "psql".to_string()),
    ]))
    .unwrap();

    send_startup_message(
        &mut write_stream,
        &StartupMessageType::StartupParameters(startup_params),
    )
    .await
    .unwrap();

    loop {
        let message = match read_backend_message(&mut read_stream).await {
            Ok(message) => message,
            Err(err) => {
                panic!("Could not read message: {:?}", err);
            }
        };

        match message {
            BackendMessageType::ReadyForQuery(_) => break,
            _ => {}
        };
    }

    Backend::new(read_stream, write_stream)
}

async fn create_frontend(stream: TcpStream) -> Frontend {
    let (read_stream, write_stream) = stream.into_split();

    Frontend::new(read_stream, write_stream)
}
