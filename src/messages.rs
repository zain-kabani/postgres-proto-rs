use bytes::{Buf, BufMut, BytesMut};
use std::{collections::HashMap, io::BufRead, mem};

use num_derive::FromPrimitive;

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

        println!("bytes: {} {:?}", final_bytes.len(), final_bytes);
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
// Authentication Response Messages

// TODO: Fix this, need to make this sub thing for auth type backend message
#[derive(FromPrimitive)]
pub enum AuthType {
    Ok = 0,
    CleartextPassword = 3,
    MD5Password = 5,
    SCMCreds = 6,
    GSS = 7,
    GSSCont = 8,
    SSPI = 9,
    SASL = 10,
    SASLContinue = 11,
    SASLFinal = 12,
}

pub trait AuthenticationMessage: Message {}

pub struct AuthenticationOk {}

impl AuthenticationOk {
    pub fn new() -> Self {
        Self {}
    }
}

impl AuthenticationMessage for AuthenticationOk {}

impl Message for AuthenticationOk {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::Ok
    }

    fn new_from_bytes(_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut auth_ok = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>(),
        );
        auth_ok.put_u8(b'R');
        auth_ok.put_i32(8);
        auth_ok.put_i32(0);

        return auth_ok;
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationCleartextPassword {
    pub bytes: BytesMut,
}

impl AuthenticationCleartextPassword {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl AuthenticationMessage for AuthenticationCleartextPassword {}

impl Message for AuthenticationCleartextPassword {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::CleartextPassword
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationMD5Password {
    pub bytes: BytesMut,
}

impl AuthenticationMD5Password {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl AuthenticationMessage for AuthenticationMD5Password {}

impl Message for AuthenticationMD5Password {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::MD5Password
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationSCMCreds {
    pub bytes: BytesMut,
}

impl AuthenticationSCMCreds {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl AuthenticationMessage for AuthenticationSCMCreds {}

impl Message for AuthenticationSCMCreds {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::SCMCreds
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationGSS {
    pub bytes: BytesMut,
}

impl AuthenticationGSS {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl AuthenticationMessage for AuthenticationGSS {}

impl Message for AuthenticationGSS {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::GSS
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationGSSCont {
    pub bytes: BytesMut,
}

impl AuthenticationGSSCont {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl AuthenticationMessage for AuthenticationGSSCont {}

impl Message for AuthenticationGSSCont {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::GSSCont
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationSSPI {
    pub bytes: BytesMut,
}

impl AuthenticationSSPI {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl AuthenticationMessage for AuthenticationSSPI {}

impl Message for AuthenticationSSPI {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::SSPI
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationSASL {
    pub bytes: BytesMut,
}

impl AuthenticationSASL {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl AuthenticationMessage for AuthenticationSASL {}

impl Message for AuthenticationSASL {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::SASL
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationSASLContinue {
    pub bytes: BytesMut,
}

impl AuthenticationSASLContinue {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl AuthenticationMessage for AuthenticationSASLContinue {}

impl Message for AuthenticationSASLContinue {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::SASLContinue
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationSASLFinal {
    pub bytes: BytesMut,
}

impl AuthenticationSASLFinal {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl AuthenticationMessage for AuthenticationSASLFinal {}

impl Message for AuthenticationSASLFinal {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::SASLFinal
    }

    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

//----------------------------------------------------------------
// Backend Messages

#[derive(FromPrimitive)]
pub enum BackendMessageType {
    ReadyForQuery = 'Z' as isize,
}

pub trait BackendMessage: Message {}

pub struct ReadyForQuery {
    pub tx_status: u8,
}

impl ReadyForQuery {
    pub fn new(tx_status: u8) -> Self {
        Self { tx_status }
    }
}

impl BackendMessage for ReadyForQuery {}

impl Message for ReadyForQuery {
    type MessageType = BackendMessageType;

    fn get_type(&self) -> Self::MessageType {
        BackendMessageType::ReadyForQuery
    }

    fn new_from_bytes(mut bytes: BytesMut) -> Result<Self, Error> {
        let tx_status = bytes.get_u8();
        Ok(Self { tx_status })
    }

    fn get_bytes(&self) -> BytesMut {
        let mut ready_for_query = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<u8>(),
        );
        ready_for_query.put_u8(b'Z');
        ready_for_query.put_i32(5);
        ready_for_query.put_u8(self.tx_status);

        return ready_for_query;
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
        let mut query = BytesMut::with_capacity(
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
