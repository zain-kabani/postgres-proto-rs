#[derive(Debug, PartialEq)]
pub enum Error {
    ParseError(String),
    SocketIOError,
    InvalidBytes,
    InvalidProtocol,
    UnsupportedProtocol,
    UnexpectedEof,
}
