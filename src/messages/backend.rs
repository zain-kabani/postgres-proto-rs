use bytes::{Buf, BufMut, BytesMut};
use num_derive::FromPrimitive;
use std::{any::Any, mem};

use crate::messages::{Error, Message};

//----------------------------------------------------------------
// Backend Messages

#[derive(FromPrimitive)]
pub enum BackendMessageType {
    ParseComplete = '1' as isize,
    BindComplete = '2' as isize,
    CloseComplete = '3' as isize,
    NotificationResponse = 'A' as isize,
    CopyDone = 'c' as isize,
    CommandComplete = 'C' as isize,
    CopyData = 'd' as isize,
    DataRow = 'D' as isize,
    ErrorResponse = 'E' as isize,
    CopyInResponse = 'G' as isize,
    CopyOutResponse = 'H' as isize,
    EmptyQueryResponse = 'I' as isize,
    BackendKeyData = 'K' as isize,
    NoData = 'n' as isize,
    NoticeResponse = 'N' as isize,
    Authentication = 'R' as isize,
    PortalSuspended = 's' as isize,
    ParameterStatus = 'S' as isize,
    ParameterDescription = 't' as isize,
    PowDescription = 'T' as isize,
    FunctionCallResponse = 'V' as isize,
    CopyBothResponse = 'W' as isize,
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
        if bytes.remaining() !=  mem::size_of::<u8>() + mem::size_of::<i32>() * 2 + mem::size_of::<u8>() {
            return Err(Error::InvalidBytes);
        }

        let _code = bytes.get_u8();
        let _len = bytes.get_i32();
        let tx_status = bytes.get_u8(); // TODO: Add validation
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

pub struct AuthenticationOk {}

impl AuthenticationOk {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for AuthenticationOk {}

impl Message for AuthenticationOk {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::Ok
    }

    fn new_from_bytes(_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut auth = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>(),
        );
        auth.put_u8(b'R');
        auth.put_i32(8);
        auth.put_i32(self.get_type() as i32);

        return auth;
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationCleartextPassword {}

impl AuthenticationCleartextPassword {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for AuthenticationCleartextPassword {}

impl Message for AuthenticationCleartextPassword {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::CleartextPassword
    }

    fn new_from_bytes(_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut auth = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>(),
        );
        auth.put_u8(b'R');
        auth.put_i32(8);
        auth.put_i32(self.get_type() as i32);

        return auth;
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AuthenticationMD5Password {
    pub salt: [u8; 4],
}

impl AuthenticationMD5Password {
    pub fn new(salt: [u8; 4]) -> Self {
        Self { salt }
    }
}

impl BackendMessage for AuthenticationMD5Password {}

impl Message for AuthenticationMD5Password {
    type MessageType = AuthType;

    fn get_type(&self) -> Self::MessageType {
        AuthType::MD5Password
    }

    fn new_from_bytes(mut bytes: BytesMut) -> Result<Self, Error> {
        if bytes.remaining() !=  mem::size_of::<u8>() + mem::size_of::<i32>() * 2 + mem::size_of::<u8>() * 4 {
            return Err(Error::InvalidBytes);
        }

        let _code = bytes.get_u8();
        let _len = bytes.get_i32();
        let _type = bytes.get_i32();
        let salt = [
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
            bytes.get_u8(),
        ];
        Ok(Self { salt })
    }

    fn get_bytes(&self) -> BytesMut {
        let mut auth = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() * 2 + mem::size_of::<u8>() * 4,
        );

        auth.put_u8(b'R');
        auth.put_i32(12);
        auth.put_i32(self.get_type() as i32);
        auth.put_slice(&self.salt);

        return auth;
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

impl BackendMessage for AuthenticationSASL {}

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

impl BackendMessage for AuthenticationSASLContinue {}

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

impl BackendMessage for AuthenticationSASLFinal {}

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
