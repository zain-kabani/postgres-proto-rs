use std::io::{BufRead, Cursor};

use bytes::BytesMut;

use crate::errors::Error;

trait BytesMutReader {
    fn read_string(&mut self) -> Result<String, Error>;
}

impl BytesMutReader for Cursor<&BytesMut> {
    fn read_string(&mut self) -> Result<String, Error> {
        let mut buf = vec![];
        match self.read_until(b'\0', &mut buf) {
            Ok(_) => {},
            Err(err) => return Err(Error::IOError(err.to_string())),
        };

        Ok(String::from_utf8_lossy(&buf[..buf.len() - 1]).to_string())
    }
}

pub trait Message {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error>
    where
        Self: Sized;

    fn get_bytes(&self) -> &BytesMut;
}

pub mod backend;
pub mod frontend;
