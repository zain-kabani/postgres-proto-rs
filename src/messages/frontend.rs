use bytes::{Buf, BufMut, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::{collections::HashMap, io::BufRead, mem};

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
    StartupParameters(StartupParameters),
    SSLRequest,
    CancelRequest(CancelRequest),
    GssEncReq,
}

impl StartupMessageType {
    pub fn get_bytes(&self) -> BytesMut {
        match self {
            StartupMessageType::StartupParameters(startup_params) => {
                return startup_params.get_bytes();
            }
            StartupMessageType::SSLRequest => {
                return SSLRequest::new().get_bytes();
            }
            StartupMessageType::CancelRequest(cancel_request) => {
                return cancel_request.get_bytes();
            }
            StartupMessageType::GssEncReq => {
                return GssEncReq::new().get_bytes();
            }
        }
    }

    pub fn new_from_bytes(code: i32, message_bytes: BytesMut) -> Result<Self, Error> {
        match FromPrimitive::from_i32(code) {
            Some(StartupMessageCodes::ProtocolVersion) => {
                let startup_message = StartupParameters::new_from_bytes(message_bytes)?;
                Ok(StartupMessageType::StartupParameters(startup_message))
            }
            Some(StartupMessageCodes::SSLRequest) => Ok(StartupMessageType::SSLRequest),
            Some(StartupMessageCodes::CancelRequest) => {
                let cancel_request = CancelRequest::new_from_bytes(message_bytes)?;
                Ok(StartupMessageType::CancelRequest(cancel_request))
            }
            Some(StartupMessageCodes::GssEncReq) => Ok(StartupMessageType::GssEncReq),
            _ => return Err(Error::InvalidProtocol),
        }
    }
}

pub trait StartupMessage: Message {}

#[derive(Debug)]
pub struct StartupParameters {
    pub protocol_version: i32,
    pub parameters: HashMap<String, String>,
}

impl StartupParameters {
    pub fn new(parameters: HashMap<String, String>) -> Result<Self, Error> {
        if !parameters.contains_key("user") {
            return Err(Error::ParseError("Missing user parameter".to_string()));
        };

        Ok(Self {
            protocol_version: 196608,
            parameters,
        })
    }
}

impl StartupMessage for StartupParameters {}

impl Message for StartupParameters {
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
        data_bytes.put_u8(b'\0');

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

        println!("final_bytes: {:?}", final_bytes);

        return final_bytes;
    }
}

#[derive(Debug)]
pub struct SSLRequest {}

impl SSLRequest {
    pub fn new() -> Self {
        Self {}
    }
}

impl StartupMessage for SSLRequest {}

impl Message for SSLRequest {
    fn new_from_bytes(_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut data_bytes = BytesMut::with_capacity(mem::size_of::<i32>() + mem::size_of::<i32>());

        data_bytes.put_i32(8);
        data_bytes.put_i32(80877103);

        return data_bytes;
    }
}

#[derive(Debug)]
pub struct CancelRequest {
    pub process_id: i32,
    pub secret_key: i32,
}

impl CancelRequest {
    pub fn new(process_id: i32, secret_key: i32) -> Self {
        Self {
            process_id,
            secret_key,
        }
    }
}

impl StartupMessage for CancelRequest {}

impl Message for CancelRequest {
    fn new_from_bytes(mut bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len() != mem::size_of::<i32>() * 4 {
            return Err(Error::InvalidBytes);
        }

        let _len = bytes.get_i32();
        let _code = bytes.get_i32();
        let process_id = bytes.get_i32();
        let secret_key = bytes.get_i32();

        Ok(Self {
            process_id,
            secret_key,
        })
    }

    fn get_bytes(&self) -> BytesMut {
        let mut data_bytes = BytesMut::with_capacity(mem::size_of::<i32>() * 4);

        data_bytes.put_i32(16);
        data_bytes.put_i32(80877102);
        data_bytes.put_i32(self.process_id);
        data_bytes.put_i32(self.secret_key);

        return data_bytes;
    }
}

#[derive(Debug)]
pub struct GssEncReq {}

impl GssEncReq {
    pub fn new() -> Self {
        Self {}
    }
}

impl StartupMessage for GssEncReq {}

impl Message for GssEncReq {
    fn new_from_bytes(_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut data_bytes = BytesMut::with_capacity(mem::size_of::<i32>() + mem::size_of::<i32>());

        data_bytes.put_i32(8);
        data_bytes.put_i32(80877104);

        return data_bytes;
    }
}

//----------------------------------------------------------------
// Frontend Messages
pub enum FrontendMessageType {
    Query(Query),
}

impl FrontendMessageType {
    pub fn get_bytes(&self) -> BytesMut {
        match self {
            FrontendMessageType::Query(query) => query.get_bytes(),
        }
    }

    pub fn new_from_bytes(msg_type: u8, message_bytes: BytesMut) -> Result<Self, Error> {
        match msg_type as char {
            'Q' => {
                let query = Query::new_from_bytes(message_bytes)?;
                Ok(Self::Query(query))
            }
            _ => Err(Error::InvalidProtocol),
        }
    }
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
    fn new_from_bytes(mut bytes: BytesMut) -> Result<Self, Error> {
        let _code = bytes.get_u8();
        let len = bytes.get_i32() as usize;
        let query_string = String::from_utf8_lossy(&bytes[..len - 5]).to_string();
        Ok(Self { query_string })
    }

    fn get_bytes(&self) -> BytesMut {
        let mut data_bytes = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<u8>(),
        );

        let msg_len = (self.query_string.len() + mem::size_of::<i32>()) as i32;

        data_bytes.put_u8(b'Q');
        data_bytes.put_i32(msg_len);
        data_bytes.put(&self.query_string.as_bytes()[..]);

        return data_bytes;
    }
}
