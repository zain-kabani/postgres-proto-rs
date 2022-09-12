use bytes::{Buf, BufMut, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::mem;

use crate::messages::{Error, Message};

//----------------------------------------------------------------
// Backend Messages

#[derive(Debug)]
pub enum BackendMessageType {
    AuthenticationCleartextPassword,
    AuthenticationMd5Password(AuthenticationMD5Password),
    AuthenticationOk,
    AuthenticationSASL(AuthenticationSASL),
    AuthenticationSASLContinue(AuthenticationSASLContinue),
    AuthenticationSASLFinal(AuthenticationSASLFinal),
    BackendKeyData(BackendKeyData),
    BindComplete,
    CloseComplete,
    CommandComplete(CommandComplete),
    CopyData(CopyData),
    CopyDone,
    CopyInResponse(CopyInResponse),
    CopyOutResponse(CopyOutResponse),
    DataRow(DataRow),
    EmptyQueryResponse,
    ErrorResponse(ErrorResponse),
    NoData,
    NoticeResponse(NoticeResponse),
    NotificationResponse(NotificationResponse),
    ParameterDescription(ParameterDescription),
    ParameterStatus(ParameterStatus),
    ParseComplete,
    PortalSuspended,
    ReadyForQuery(ReadyForQuery),
    RowDescription(RowDescription),
}

impl BackendMessageType {
    pub fn get_bytes(&self) -> BytesMut {
        match self {
            Self::AuthenticationCleartextPassword => {
                AuthenticationCleartextPassword::new().get_bytes()
            }
            Self::AuthenticationMd5Password(md5_password) => md5_password.get_bytes(),
            Self::AuthenticationOk => AuthenticationOk::new().get_bytes(),
            Self::AuthenticationSASL(sasl) => sasl.get_bytes(),
            Self::AuthenticationSASLContinue(sasl_cont) => sasl_cont.get_bytes(),
            Self::AuthenticationSASLFinal(sasl_final) => sasl_final.get_bytes(),
            Self::BackendKeyData(data) => data.get_bytes(),
            Self::BindComplete => BindComplete::new().get_bytes(),
            Self::CloseComplete => CloseComplete::new().get_bytes(),
            Self::CommandComplete(command_complete) => command_complete.get_bytes(),
            Self::CopyData(copy_data) => copy_data.get_bytes(),
            Self::CopyDone => CopyDone::new().get_bytes(),
            Self::CopyInResponse(copy_in_response) => copy_in_response.get_bytes(),
            Self::CopyOutResponse(copy_out_response) => copy_out_response.get_bytes(),
            Self::DataRow(row_data) => row_data.get_bytes(),
            Self::EmptyQueryResponse => EmptyQueryResponse::new().get_bytes(),
            Self::ErrorResponse(error_response) => error_response.get_bytes(),
            Self::NoData => NoData::new().get_bytes(),
            Self::NoticeResponse(notice_response) => notice_response.get_bytes(),
            Self::NotificationResponse(notif_resp) => notif_resp.get_bytes(),
            Self::ParameterDescription(param_desc) => param_desc.get_bytes(),
            Self::ParameterStatus(parameter_status) => parameter_status.get_bytes(),
            Self::ParseComplete => ParseComplete::new().get_bytes(),
            Self::PortalSuspended => PortalSuspended::new().get_bytes(),
            Self::ReadyForQuery(ready_for_query) => ready_for_query.get_bytes(),
            Self::RowDescription(row_description) => row_description.get_bytes(),
        }
    }

    pub fn new_from_bytes(msg_type: u8, message_bytes: BytesMut) -> Result<Self, Error> {
        match msg_type as char {
            'R' => {
                let auth_type = match message_bytes.get(5..9) {
                    Some(auth_type_bytes) => {
                        i32::from_be_bytes(match <[u8; 4]>::try_from(auth_type_bytes) {
                            Ok(auth_type) => auth_type,
                            Err(_) => return Err(Error::InvalidBytes),
                        })
                    }
                    None => return Err(Error::InvalidBytes),
                };

                match FromPrimitive::from_i32(auth_type) {
                    Some(AuthType::Ok) => Ok(Self::AuthenticationOk),
                    Some(AuthType::CleartextPassword) => Ok(Self::AuthenticationCleartextPassword),
                    Some(AuthType::MD5Password) => {
                        let md5_password =
                            AuthenticationMD5Password::new_from_bytes(message_bytes)?;
                        Ok(Self::AuthenticationMd5Password(md5_password))
                    }
                    Some(AuthType::SASL) => {
                        let sasl = AuthenticationSASL::new_from_bytes(message_bytes)?;
                        Ok(Self::AuthenticationSASL(sasl))
                    }
                    Some(AuthType::SASLContinue) => {
                        let sasl_cont = AuthenticationSASLContinue::new_from_bytes(message_bytes)?;
                        Ok(Self::AuthenticationSASLContinue(sasl_cont))
                    }
                    Some(AuthType::SASLFinal) => {
                        let sasl_final = AuthenticationSASLFinal::new_from_bytes(message_bytes)?;
                        Ok(Self::AuthenticationSASLFinal(sasl_final))
                    }
                    Some(AuthType::SCMCreds)
                    | Some(AuthType::GSS)
                    | Some(AuthType::GSSCont)
                    | Some(AuthType::SSPI) => Err(Error::UnsupportedProtocol),
                    _ => return Err(Error::InvalidProtocol),
                }
            }
            'E' => {
                let message = ErrorResponse::new_from_bytes(message_bytes)?;
                Ok(Self::ErrorResponse(message))
            }
            'Z' => {
                let ready_for_query = ReadyForQuery::new_from_bytes(message_bytes)?;
                Ok(Self::ReadyForQuery(ready_for_query))
            }

            _ => return Err(Error::InvalidProtocol),
        }
    }
}

pub trait BackendMessage: Message {}

#[derive(Debug)]
pub struct ParseComplete {}

impl ParseComplete {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for ParseComplete {}

impl Message for ParseComplete {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut parse_complete =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        parse_complete.put_u8(b'1');
        parse_complete.put_i32(4);

        return parse_complete;
    }
}

#[derive(Debug)]
pub struct BindComplete {}

impl BindComplete {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for BindComplete {}

impl Message for BindComplete {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut bind_complete =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        bind_complete.put_u8(b'2');
        bind_complete.put_i32(4);

        return bind_complete;
    }
}

#[derive(Debug)]
pub struct CloseComplete {}

impl CloseComplete {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for CloseComplete {}

impl Message for CloseComplete {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut close_complete =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        close_complete.put_u8(b'3');
        close_complete.put_i32(4);

        return close_complete;
    }
}

#[derive(Debug)]
pub struct NotificationResponse {
    pub bytes: BytesMut,
}

impl NotificationResponse {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for NotificationResponse {}

impl Message for NotificationResponse {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct CopyDone {}

impl CopyDone {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for CopyDone {}

impl Message for CopyDone {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut copy_done = BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        copy_done.put_u8(b'c');
        copy_done.put_i32(4);

        return copy_done;
    }
}

#[derive(Debug)]
pub struct CommandComplete {
    pub bytes: BytesMut,
}

impl CommandComplete {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for CommandComplete {}

impl Message for CommandComplete {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct CopyData {
    pub bytes: BytesMut,
}

impl CopyData {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for CopyData {}

impl Message for CopyData {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct DataRow {
    pub bytes: BytesMut,
}

impl DataRow {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for DataRow {}

impl Message for DataRow {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct ErrorResponse {
    pub bytes: BytesMut,
}

impl ErrorResponse {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for ErrorResponse {}

impl Message for ErrorResponse {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct CopyInResponse {
    pub bytes: BytesMut,
}

impl CopyInResponse {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for CopyInResponse {}

impl Message for CopyInResponse {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct CopyOutResponse {
    pub bytes: BytesMut,
}

impl CopyOutResponse {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for CopyOutResponse {}

impl Message for CopyOutResponse {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct EmptyQueryResponse {}

impl EmptyQueryResponse {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for EmptyQueryResponse {}

impl Message for EmptyQueryResponse {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut empty_query_response =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        empty_query_response.put_u8(b'I');
        empty_query_response.put_i32(4);

        return empty_query_response;
    }
}

#[derive(Debug)]
pub struct BackendKeyData {
    pub process_id: i32,
    pub secret_key: i32,
}

impl BackendKeyData {
    pub fn new(process_id: i32, secret_key: i32) -> Self {
        Self {
            process_id,
            secret_key,
        }
    }
}

impl BackendMessage for BackendKeyData {}

impl Message for BackendKeyData {
    fn new_from_bytes(mut bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len()
            != mem::size_of::<u8>()
                + mem::size_of::<i32>()
                + mem::size_of::<i32>()
                + mem::size_of::<i32>()
        {
            return Err(Error::InvalidBytes);
        }

        let _code = bytes.get_u8();
        let _len = bytes.get_i32();
        let process_id = bytes.get_i32();
        let secret_key = bytes.get_i32();

        Ok(Self {
            process_id,
            secret_key,
        })
    }

    fn get_bytes(&self) -> BytesMut {
        let mut backend_key_data = BytesMut::with_capacity(
            mem::size_of::<u8>()
                + mem::size_of::<i32>()
                + mem::size_of::<i32>()
                + mem::size_of::<i32>(),
        );

        backend_key_data.put_u8(b'K');
        backend_key_data.put_i32(12);
        backend_key_data.put_i32(self.process_id);
        backend_key_data.put_i32(self.secret_key);

        return backend_key_data;
    }
}

#[derive(Debug)]
pub struct NoData {}

impl NoData {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for NoData {}

impl Message for NoData {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut backend_key_data =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        backend_key_data.put_u8(b'n');
        backend_key_data.put_i32(4);

        return backend_key_data;
    }
}

#[derive(Debug)]
pub struct NoticeResponse {
    pub bytes: BytesMut,
}

impl NoticeResponse {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for NoticeResponse {}

impl Message for NoticeResponse {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct ParameterDescription {
    pub bytes: BytesMut,
}

impl ParameterDescription {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for ParameterDescription {}

impl Message for ParameterDescription {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct ParameterStatus {
    pub bytes: BytesMut,
}

impl ParameterStatus {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for ParameterStatus {}

impl Message for ParameterStatus {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct RowDescription {
    pub bytes: BytesMut,
}

impl RowDescription {
    pub fn new(bytes: BytesMut) -> Self {
        Self { bytes }
    }
}

impl BackendMessage for RowDescription {}

impl Message for RowDescription {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
pub struct PortalSuspended {}

impl PortalSuspended {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for PortalSuspended {}

impl Message for PortalSuspended {
    fn new_from_bytes(_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut data_bytes = BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        data_bytes.put_u8(b's');
        data_bytes.put_i32(4);

        return data_bytes;
    }
}

#[derive(Debug)]
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
    fn new_from_bytes(mut bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() * 2 + mem::size_of::<u8>() {
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

#[derive(Debug)]
pub struct AuthenticationOk {}

impl AuthenticationOk {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for AuthenticationOk {}

impl Message for AuthenticationOk {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut auth = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>(),
        );
        auth.put_u8(b'R');
        auth.put_i32(8);
        auth.put_i32(AuthType::Ok as i32);

        return auth;
    }
}

#[derive(Debug)]
pub struct AuthenticationCleartextPassword {}

impl AuthenticationCleartextPassword {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for AuthenticationCleartextPassword {}

impl Message for AuthenticationCleartextPassword {
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self {})
    }

    fn get_bytes(&self) -> BytesMut {
        let mut auth = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>(),
        );
        auth.put_u8(b'R');
        auth.put_i32(8);
        auth.put_i32(AuthType::CleartextPassword as i32);

        return auth;
    }
}

#[derive(Debug)]
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
    fn new_from_bytes(mut bytes: BytesMut) -> Result<Self, Error> {
        if bytes.len()
            != mem::size_of::<u8>() + mem::size_of::<i32>() * 2 + mem::size_of::<u8>() * 4
        {
            return Err(Error::InvalidBytes);
        }

        let _code = bytes.get_u8();
        let _len = bytes.get_i32();
        let _type = bytes.get_i32();

        // These unwraps are safe because of validation above
        let salt: [u8; 4] = bytes.get(0..4).unwrap().try_into().unwrap();

        Ok(Self { salt })
    }

    fn get_bytes(&self) -> BytesMut {
        let mut auth = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() * 2 + mem::size_of::<u8>() * 4,
        );

        auth.put_u8(b'R');
        auth.put_i32(12);
        auth.put_i32(AuthType::MD5Password as i32);
        auth.put_slice(&self.salt);

        return auth;
    }
}

#[derive(Debug)]
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
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
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
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}

#[derive(Debug)]
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
    fn new_from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.bytes.clone();
    }
}
