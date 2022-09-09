use bytes::{Buf, BufMut, BytesMut};
use num_derive::FromPrimitive;
use std::{any::Any, collections::HashMap, io::BufRead, mem};

use crate::messages::{Error, Message};

//----------------------------------------------------------------
// Startup Messages

#[derive(FromPrimitive)]
pub enum StartupMessageCodes {
    ProtocolVersion = 196608,
    SSLRequest = 80877103,
    CancelRequest = 80877102,
    GssEncReq = 80877104,
}

#[derive(Debug)]
pub enum StartupMessageType {
    StartupParameters,
    SSLRequest,
    CancelRequest,
    GssEncReq,
}

pub trait StartupMessage: Message {}

#[derive(Debug)]
pub struct StartupParameters {
    pub protocol_version: i32,
    pub parameters: HashMap<String, String>,
}

impl StartupParameters {
    pub fn new(protocol_version: i32, parameters: HashMap<String, String>) -> Self {
        // if !parameters.contains_key("user") {
        //     return Err(Error::ParseError("Missing user parameter".to_string()));
        // };

        Self {
            protocol_version,
            parameters,
        }
    }
}

impl StartupMessage for StartupParameters {}

impl Message for StartupParameters {
    type MessageType = StartupMessageType;

    fn get_type(&self) -> Self::MessageType {
        StartupMessageType::StartupParameters
    }

    fn new_from_bytes(mut bytes: BytesMut) -> Result<Self, Error> {
        let _len = bytes.get_i32();

        let protocol_version = bytes.get_i32();

        let mut split_iter = bytes.reader().split(b'\0');

        let mut parameters = HashMap::new();

        loop {
            let key = String::from_utf8_lossy(&split_iter.next().unwrap().unwrap()).to_string(); // TODO: handle error
            if key.len() == 0 {
                break;
            }
            let value = String::from_utf8_lossy(&split_iter.next().unwrap().unwrap()).to_string();
            parameters.insert(key, value);
        }

        if !parameters.contains_key("user") {
            return Err(Error::ParseError("Missing user parameter".to_string()));
        }

        Ok(Self {
            protocol_version,
            parameters,
        })
    }

    fn get_bytes(&self) -> BytesMut {
        let mut data_bytes = BytesMut::new();

        data_bytes.put_i32(self.protocol_version);

        for (key, value) in &self.parameters {
            data_bytes.put(key.as_bytes());
            data_bytes.put_u8(b'\0');
            data_bytes.put(value.as_bytes());
            data_bytes.put_u8(b'\0');
        }
        data_bytes.put_u8(b'\0');

        let mut final_bytes = BytesMut::with_capacity(data_bytes.len() + mem::size_of::<i32>());

        final_bytes.put_i32(data_bytes.len() as i32);
        final_bytes.put(data_bytes.freeze());

        return final_bytes;
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
pub struct SSLRequest {
    pub bytes: BytesMut,
}

impl SSLRequest {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl StartupMessage for SSLRequest {}

impl Message for SSLRequest {
    type MessageType = StartupMessageType;

    fn get_type(&self) -> Self::MessageType {
        StartupMessageType::SSLRequest
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        self.bytes.clone()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
pub struct CancelRequest {
    pub bytes: BytesMut,
}

impl CancelRequest {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl StartupMessage for CancelRequest {}

impl Message for CancelRequest {
    type MessageType = StartupMessageType;

    fn get_type(&self) -> Self::MessageType {
        StartupMessageType::CancelRequest
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        self.bytes.clone()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
pub struct GssEncReq {
    pub bytes: BytesMut,
}

impl GssEncReq {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl StartupMessage for GssEncReq {}

impl Message for GssEncReq {
    type MessageType = StartupMessageType;

    fn get_type(&self) -> Self::MessageType {
        StartupMessageType::GssEncReq
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        self.bytes.clone()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

//----------------------------------------------------------------
// Frontend Messages
pub enum FrontendMessageType {
    Query = 'Q' as isize,
}

pub trait FrontendMessage: Message {}

pub struct Query {
    pub query_string: String,
}

impl Query {
    pub fn new(query_string: String) -> Self {
        Self { query_string }
    }
}

impl FrontendMessage for Query {}

impl Message for Query {
    type MessageType = FrontendMessageType;

    fn get_type(&self) -> Self::MessageType {
        FrontendMessageType::Query
    }

    fn new_from_bytes(mut bytes: BytesMut) -> Result<Self, Error> {
        let _code = bytes.get_u8();
        let len = bytes.get_i32() as usize;
        let query_string = String::from_utf8_lossy(&bytes[..len - 5]).to_string();
        Ok(Self { query_string })
    }

    fn get_bytes(&self) -> BytesMut {
        let query = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<u8>(),
        );
        // ready_for_query.put_u8(b'Z');
        // ready_for_query.put_i32(5);
        // ready_for_query.put_u8(self.tx_status);

        return query;
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
