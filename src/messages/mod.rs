use bytes::BytesMut;

use crate::errors::Error;

pub trait Message {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error>
    where
        Self: Sized;

    fn get_bytes(&self) -> BytesMut;
}

pub mod backend;
pub mod frontend;
