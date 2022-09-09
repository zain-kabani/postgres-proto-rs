use bytes::{Buf, BufMut, BytesMut};
use num_derive::FromPrimitive;
use std::{any::Any, mem};

use crate::messages::{Error, Message};

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
