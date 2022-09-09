
use postgres_proto_rs::{tokio::*};
use postgres_proto_rs::messages::{backend::*, frontend::*};
use tokio::net::TcpListener;



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
            _ => {}
        }

        send_authentication_message(&mut write_stream, AuthenticationOk::new()).await;

        send_backend_message(&mut write_stream, ReadyForQuery::new(b'Z')).await;

        let res = read_frontend_message(&mut read_stream).await.unwrap();

        match res.get_type() {
            FrontendMessageType::Query => {
                let query = res.as_any().downcast_ref::<Query>().unwrap();
                println!("Got query {:?}", query.query_string);
            }
        }
        send_backend_message(&mut write_stream, ReadyForQuery::new(b'Z')).await;


        let res = read_frontend_message(&mut read_stream).await.unwrap();

        match res.get_type() {
            FrontendMessageType::Query => {
                let query = res.as_any().downcast_ref::<Query>().unwrap();
                println!("Got query {:?}", query.query_string);
            }
        }
    }
}
