use bytes::BytesMut;
use std::any::Any;

use crate::errors::Error;

pub trait Message {
    type MessageType;
    fn get_type(&self) -> Self::MessageType;

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error>
    where
        Self: Sized;

    fn get_bytes(&self) -> BytesMut;

    fn as_any(&self) -> &dyn Any;
}

pub mod backend;
pub mod frontend;
