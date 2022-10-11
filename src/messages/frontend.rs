use bytes::{Buf, BufMut, BytesMut};
use std::{collections::HashMap, io::Cursor, mem};

use crate::messages::{BytesMutReader, Error, Message};

//----------------------------------------------------------------
// Startup Messages

pub const PROTOCOL_VERSION_CODE: i32 = 196608;
pub const SSL_REQUEST_CODE: i32 = 80877103;
pub const CANCEL_REQUEST_CODE: i32 = 80877102;
pub const GSS_ENC_REQ_CODE: i32 = 80877104;

#[derive(Debug)]
pub enum StartupMessageType {
    StartupParameters(StartupParameters),
    SSLRequest(SSLRequest),
    CancelRequest(CancelRequest),
    GssEncReq(GssEncReq),
}

impl StartupMessageType {
    pub fn get_bytes(&self) -> &BytesMut {
        match self {
            StartupMessageType::StartupParameters(startup_params) => {
                return startup_params.get_bytes();
            }
            StartupMessageType::SSLRequest(ssl_request) => {
                return ssl_request.get_bytes();
            }
            StartupMessageType::CancelRequest(cancel_request) => {
                return cancel_request.get_bytes();
            }
            StartupMessageType::GssEncReq(gss_enc_req) => {
                return gss_enc_req.get_bytes();
            }
        }
    }

    pub fn new_from_bytes(code: i32, message_bytes: BytesMut) -> Result<Self, Error> {
        match code {
            PROTOCOL_VERSION_CODE => {
                let startup_message = StartupParameters::new_from_bytes(message_bytes)?;
                Ok(StartupMessageType::StartupParameters(startup_message))
            }
            SSL_REQUEST_CODE => {
                let ssl_request = SSLRequest::new_from_bytes(message_bytes)?;
                Ok(StartupMessageType::SSLRequest(ssl_request))
            }
            CANCEL_REQUEST_CODE => {
                let cancel_request = CancelRequest::new_from_bytes(message_bytes)?;
                Ok(StartupMessageType::CancelRequest(cancel_request))
            }
            GSS_ENC_REQ_CODE => {
                let gss_enc_req = GssEncReq::new_from_bytes(message_bytes)?;
                Ok(StartupMessageType::GssEncReq(gss_enc_req))
            }
            _ => return Err(Error::InvalidProtocol),
        }
    }
}

pub trait StartupMessage: Message {}

#[derive(Debug)]
pub struct StartupParameters {
    message_bytes: BytesMut,
}

pub struct StartupParametersParams {
    pub parameters: HashMap<String, String>,
}

impl StartupParameters {
    pub fn new(parameters: HashMap<String, String>) -> Result<Self, Error> {
        if !parameters.contains_key("user") {
            return Err(Error::ParseError("Missing user parameter".to_string()));
        };

        let mut data_bytes = BytesMut::new();

        data_bytes.put_i32(PROTOCOL_VERSION_CODE);

        for (key, value) in &parameters {
            data_bytes.put(key.as_bytes());
            data_bytes.put_u8(b'\0');
            data_bytes.put(value.as_bytes());
            data_bytes.put_u8(b'\0');
        }
        data_bytes.put_u8(b'\0');

        let mut message_bytes = BytesMut::with_capacity(data_bytes.len() + mem::size_of::<i32>());

        message_bytes.put_i32(data_bytes.len() as i32 + mem::size_of::<i32>() as i32);
        message_bytes.put(data_bytes);

        Ok(Self { message_bytes })
    }

    pub fn get_params(&self) -> StartupParametersParams {
        let mut cursor = Cursor::new(&self.message_bytes);

        let _len = cursor.get_i32();
        let _protocol_version = cursor.get_i32();

        let mut parameters = HashMap::new();

        loop {
            let key = match cursor.read_string() {
                Ok(s) => {
                    if s.len() == 0 {
                        break;
                    } else {
                        s
                    }
                }
                Err(_) => break, // TODO: handle error
            };

            let value = cursor.read_string().unwrap();

            parameters.insert(key, value);
        }

        StartupParametersParams { parameters }
    }
}

impl StartupMessage for StartupParameters {}

impl Message for StartupParameters {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self {
            message_bytes: message_bytes,
        })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct SSLRequest {
    message_bytes: BytesMut,
}

impl SSLRequest {
    pub fn new() -> Self {
        let mut message_bytes =
            BytesMut::with_capacity(mem::size_of::<i32>() + mem::size_of::<i32>());

        message_bytes.put_i32(8);
        message_bytes.put_i32(SSL_REQUEST_CODE);

        Self { message_bytes }
    }
}

impl StartupMessage for SSLRequest {}

impl Message for SSLRequest {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct CancelRequest {
    message_bytes: BytesMut,
}

pub struct CancelRequestParams {
    pub process_id: i32,
    pub secret_key: i32,
}

impl CancelRequest {
    pub fn new(process_id: i32, secret_key: i32) -> Self {
        let mut message_bytes = BytesMut::with_capacity(mem::size_of::<i32>() * 4);

        message_bytes.put_i32(16);
        message_bytes.put_i32(CANCEL_REQUEST_CODE);
        message_bytes.put_i32(process_id);
        message_bytes.put_i32(secret_key);

        Self { message_bytes }
    }

    pub fn get_params(&self) -> CancelRequestParams {
        let mut cursor = Cursor::new(&self.message_bytes);

        let _len = cursor.get_i32();
        let _code = cursor.get_i32();
        let process_id = cursor.get_i32();
        let secret_key = cursor.get_i32();

        CancelRequestParams {
            process_id,
            secret_key,
        }
    }
}

impl StartupMessage for CancelRequest {}

impl Message for CancelRequest {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<i32>() * 4 {
            return Err(Error::InvalidBytes);
        }

        Ok(Self {
            message_bytes: message_bytes,
        })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct GssEncReq {
    message_bytes: BytesMut,
}

impl GssEncReq {
    pub fn new() -> Self {
        let mut message_bytes =
            BytesMut::with_capacity(mem::size_of::<i32>() + mem::size_of::<i32>());

        message_bytes.put_i32(8);
        message_bytes.put_i32(GSS_ENC_REQ_CODE);

        Self { message_bytes }
    }
}

impl StartupMessage for GssEncReq {}

impl Message for GssEncReq {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

//----------------------------------------------------------------
// Frontend Messages
#[derive(Debug)]
pub enum FrontendMessageType {
    Query(Query),
    Bind(Bind),
    Close(Close),
    Describe(Describe),
    Execute(Execute),
    FunctionCall(FunctionCall),
    CopyFail(CopyFail),
    CopyData(CopyData),
    CopyDone(CopyDone),
    Flush(Flush),
    Parse(Parse),
    Sync(Sync),
    Terminate(Terminate),
}

impl FrontendMessageType {
    pub fn get_bytes(&self) -> &BytesMut {
        match self {
            Self::Query(query) => query.get_bytes(),
            Self::Bind(bind) => bind.get_bytes(),
            Self::Close(close) => close.get_bytes(),
            Self::Describe(describe) => describe.get_bytes(),
            Self::Execute(execute) => execute.get_bytes(),
            Self::FunctionCall(function_call) => function_call.get_bytes(),
            Self::CopyFail(copy_fail) => copy_fail.get_bytes(),
            Self::CopyData(copy_data) => copy_data.get_bytes(),
            Self::CopyDone(copy_done) => copy_done.get_bytes(),
            Self::Flush(flush) => flush.get_bytes(),
            Self::Parse(parse) => parse.get_bytes(),
            Self::Sync(sync) => sync.get_bytes(),
            Self::Terminate(terminate) => terminate.get_bytes(),
        }
    }

    pub fn new_from_bytes(msg_type: u8, message_bytes: BytesMut) -> Result<Self, Error> {
        match msg_type as char {
            'Q' => {
                let query = Query::new_from_bytes(message_bytes)?;
                Ok(Self::Query(query))
            }
            'B' => {
                let bind = Bind::new_from_bytes(message_bytes)?;
                Ok(Self::Bind(bind))
            }
            'C' => {
                let close = Close::new_from_bytes(message_bytes)?;
                Ok(Self::Close(close))
            }
            'D' => {
                let describe = Describe::new_from_bytes(message_bytes)?;
                Ok(Self::Describe(describe))
            }
            'E' => {
                let execute = Execute::new_from_bytes(message_bytes)?;
                Ok(Self::Execute(execute))
            }
            'F' => {
                let function_call = FunctionCall::new_from_bytes(message_bytes)?;
                Ok(Self::FunctionCall(function_call))
            }
            'f' => {
                let copy_fail = CopyFail::new_from_bytes(message_bytes)?;
                Ok(Self::CopyFail(copy_fail))
            }
            'd' => {
                let copy_data = CopyData::new_from_bytes(message_bytes)?;
                Ok(Self::CopyData(copy_data))
            }
            'c' => {
                let copy_done = CopyDone::new_from_bytes(message_bytes)?;
                Ok(Self::CopyDone(copy_done))
            }
            'H' => {
                let flush = Flush::new_from_bytes(message_bytes)?;
                Ok(Self::Flush(flush))
            }
            'P' => {
                let parse = Parse::new_from_bytes(message_bytes)?;
                Ok(Self::Parse(parse))
            }
            'S' => {
                let sync = Sync::new_from_bytes(message_bytes)?;
                Ok(Self::Sync(sync))
            }
            'X' => {
                let terminate = Terminate::new_from_bytes(message_bytes)?;
                Ok(Self::Terminate(terminate))
            }
            _ => Err(Error::InvalidProtocol),
        }
    }
}

pub trait FrontendMessage: Message {}

#[derive(Debug)]
pub struct Terminate {
    message_bytes: BytesMut,
}

impl Terminate {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for Terminate {}

impl Message for Terminate {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct Sync {
    message_bytes: BytesMut,
}

impl Sync {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for Sync {}

impl Message for Sync {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct Parse {
    message_bytes: BytesMut,
}

impl Parse {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for Parse {}

impl Message for Parse {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct Flush {
    message_bytes: BytesMut,
}

impl Flush {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for Flush {}

impl Message for Flush {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct CopyDone {
    message_bytes: BytesMut,
}

impl CopyDone {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for CopyDone {}

impl Message for CopyDone {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct CopyData {
    message_bytes: BytesMut,
}

impl CopyData {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for CopyData {}

impl Message for CopyData {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct CopyFail {
    message_bytes: BytesMut,
}

impl CopyFail {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for CopyFail {}

impl Message for CopyFail {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct FunctionCall {
    message_bytes: BytesMut,
}

impl FunctionCall {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for FunctionCall {}

impl Message for FunctionCall {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct Execute {
    message_bytes: BytesMut,
}

impl Execute {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for Execute {}

impl Message for Execute {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct Describe {
    message_bytes: BytesMut,
}

impl Describe {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for Describe {}

impl Message for Describe {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct Close {
    message_bytes: BytesMut,
}

impl Close {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for Close {}

impl Message for Close {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct Bind {
    message_bytes: BytesMut,
}

impl Bind {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl FrontendMessage for Bind {}

impl Message for Bind {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        &self.message_bytes
    }
}

#[derive(Debug)]
pub struct Query {
    message_bytes: BytesMut,
}

pub struct QueryParams {
    pub query_string: String,
}

impl Query {
    pub fn new(query_string: String) -> Self {
        let mut message_bytes = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<u8>(),
        );

        let msg_len = (query_string.len() + 1 + mem::size_of::<i32>()) as i32;

        message_bytes.put_u8(b'Q');
        message_bytes.put_i32(msg_len);
        message_bytes.put(&query_string.as_bytes()[..]);
        message_bytes.put_u8(0);

        Self { message_bytes }
    }

    pub fn get_params(&self) -> QueryParams {
        let mut cursor = Cursor::new(&self.message_bytes);

        let _code = cursor.get_u8();
        let _len = cursor.get_i32();

        let query_string = cursor.read_string().unwrap();

        QueryParams {
            query_string: query_string,
        }
    }
}

impl FrontendMessage for Query {}

impl Message for Query {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}
