use bytes::{Buf, BufMut, BytesMut};
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
    FunctionCallResponse(FunctionCallResponse),
    CopyBothResponse(CopyBothResponse),
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
            Self::FunctionCallResponse(function_call_resp) => function_call_resp.get_bytes(),
            Self::CopyBothResponse(copy_both_resp) => copy_both_resp.get_bytes(),
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

                match auth_type {
                    AUTH_CODE_OK => Ok(Self::AuthenticationOk),
                    AUTH_CODE_CLEARTEXT_PASSWORD => Ok(Self::AuthenticationCleartextPassword),
                    AUTH_CODE_MD5_PASSWORD => {
                        let md5_password =
                            AuthenticationMD5Password::new_from_bytes(message_bytes)?;
                        Ok(Self::AuthenticationMd5Password(md5_password))
                    }
                    AUTH_CODE_SASL => {
                        let sasl = AuthenticationSASL::new_from_bytes(message_bytes)?;
                        Ok(Self::AuthenticationSASL(sasl))
                    }
                    AUTH_CODE_SASL_CONTINUE => {
                        let sasl_cont = AuthenticationSASLContinue::new_from_bytes(message_bytes)?;
                        Ok(Self::AuthenticationSASLContinue(sasl_cont))
                    }
                    AUTH_CODE_SASL_FINAL => {
                        let sasl_final = AuthenticationSASLFinal::new_from_bytes(message_bytes)?;
                        Ok(Self::AuthenticationSASLFinal(sasl_final))
                    }
                    AUTH_CODE_SCM_CREDS | AUTH_CODE_GSS | AUTH_CODE_GSS_CONT | AUTH_CODE_SSPI => {
                        Err(Error::UnsupportedProtocol)
                    }
                    _ => return Err(Error::InvalidProtocol),
                }
            }
            'E' => {
                let message = ErrorResponse::new_from_bytes(message_bytes)?;
                Ok(Self::ErrorResponse(message))
            }
            'S' => {
                let message = ParameterStatus::new_from_bytes(message_bytes)?;
                Ok(Self::ParameterStatus(message))
            }
            'K' => {
                let message = BackendKeyData::new_from_bytes(message_bytes)?;
                Ok(Self::BackendKeyData(message))
            }
            'T' => {
                let message = RowDescription::new_from_bytes(message_bytes)?;
                Ok(Self::RowDescription(message))
            }
            'D' => {
                let message = DataRow::new_from_bytes(message_bytes)?;
                Ok(Self::DataRow(message))
            }
            'C' => {
                let message = CommandComplete::new_from_bytes(message_bytes)?;
                Ok(Self::CommandComplete(message))
            }
            'Z' => {
                let ready_for_query = ReadyForQuery::new_from_bytes(message_bytes)?;
                Ok(Self::ReadyForQuery(ready_for_query))
            }
            '1' => Ok(Self::ParseComplete),
            '2' => Ok(Self::BindComplete),
            '3' => Ok(Self::CloseComplete),
            'A' => {
                let notification_response = NotificationResponse::new_from_bytes(message_bytes)?;
                Ok(Self::NotificationResponse(notification_response))
            }
            'c' => Ok(Self::CopyDone),
            'd' => {
                let copy_data = CopyData::new_from_bytes(message_bytes)?;
                Ok(Self::CopyData(copy_data))
            }
            'G' => {
                let copy_in_response = CopyInResponse::new_from_bytes(message_bytes)?;
                Ok(Self::CopyInResponse(copy_in_response))
            }
            'H' => {
                let copy_out_response = CopyOutResponse::new_from_bytes(message_bytes)?;
                Ok(Self::CopyOutResponse(copy_out_response))
            }
            'I' => Ok(Self::EmptyQueryResponse),
            'n' => Ok(Self::NoData),
            'N' => {
                let notice_response = NoticeResponse::new_from_bytes(message_bytes)?;
                Ok(Self::NoticeResponse(notice_response))
            }
            's' => Ok(Self::PortalSuspended),
            't' => {
                let parameter_description = ParameterDescription::new_from_bytes(message_bytes)?;
                Ok(Self::ParameterDescription(parameter_description))
            }
            'V' => {
                let function_call_response = FunctionCallResponse::new_from_bytes(message_bytes)?;
                Ok(Self::FunctionCallResponse(function_call_response))
            }
            'W' => {
                let copy_both_response = CopyBothResponse::new_from_bytes(message_bytes)?;
                Ok(Self::CopyBothResponse(copy_both_response))
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
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
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
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
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
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
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
    message_bytes: BytesMut,
}

impl NotificationResponse {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for NotificationResponse {}

impl Message for NotificationResponse {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct FunctionCallResponse {
    message_bytes: BytesMut,
}

impl FunctionCallResponse {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for FunctionCallResponse {}

impl Message for FunctionCallResponse {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct CopyBothResponse {
    message_bytes: BytesMut,
}

impl CopyBothResponse {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for CopyBothResponse {}

impl Message for CopyBothResponse {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
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
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
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
    pub command_tag: String,
}

impl CommandComplete {
    pub fn new(command_tag: String) -> Self {
        Self { command_tag }
    }
}

impl BackendMessage for CommandComplete {}

impl Message for CommandComplete {
    fn new_from_bytes(mut message_bytes: BytesMut) -> Result<Self, Error> {
        let _code = message_bytes.get_u8();
        let len = message_bytes.get_i32() as usize;

        let command_tag = String::from_utf8_lossy(&message_bytes[..len - 5]).to_string();

        Ok(Self { command_tag })
    }

    fn get_bytes(&self) -> BytesMut {
        let mut message_bytes = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<u8>(),
        );

        let msg_len = (self.command_tag.len() + 1 + mem::size_of::<i32>()) as i32;

        message_bytes.put_u8(b'C');
        message_bytes.put_i32(msg_len);
        message_bytes.put(&self.command_tag.as_bytes()[..]);
        message_bytes.put_u8(0);

        return message_bytes;
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

impl BackendMessage for CopyData {}

impl Message for CopyData {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct DataRow {
    message_bytes: BytesMut,
}

impl DataRow {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for DataRow {}

impl Message for DataRow {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct ErrorResponse {
    message_bytes: BytesMut,
}

impl ErrorResponse {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for ErrorResponse {}

impl Message for ErrorResponse {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct CopyInResponse {
    message_bytes: BytesMut,
}

impl CopyInResponse {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for CopyInResponse {}

impl Message for CopyInResponse {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct CopyOutResponse {
    message_bytes: BytesMut,
}

impl CopyOutResponse {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for CopyOutResponse {}

impl Message for CopyOutResponse {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
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
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
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
    fn new_from_bytes(mut message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len()
            != mem::size_of::<u8>()
                + mem::size_of::<i32>()
                + mem::size_of::<i32>()
                + mem::size_of::<i32>()
        {
            return Err(Error::InvalidBytes);
        }

        let _code = message_bytes.get_u8();
        let _len = message_bytes.get_i32();
        let process_id = message_bytes.get_i32();
        let secret_key = message_bytes.get_i32();

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
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
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
    message_bytes: BytesMut,
}

impl NoticeResponse {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for NoticeResponse {}

impl Message for NoticeResponse {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct ParameterDescription {
    message_bytes: BytesMut,
}

impl ParameterDescription {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for ParameterDescription {}

impl Message for ParameterDescription {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct ParameterStatus {
    message_bytes: BytesMut,
}

impl ParameterStatus {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for ParameterStatus {}

impl Message for ParameterStatus {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct RowDescription {
    message_bytes: BytesMut,
}

impl RowDescription {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for RowDescription {}

impl Message for RowDescription {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
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
    fn new_from_bytes(mut message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<u8>() {
            return Err(Error::InvalidBytes);
        }

        let _code = message_bytes.get_u8();
        let _len = message_bytes.get_i32();
        let tx_status = message_bytes.get_u8(); // TODO: Add validation
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

pub const AUTH_CODE_OK: i32 = 0;
pub const AUTH_CODE_CLEARTEXT_PASSWORD: i32 = 3;
pub const AUTH_CODE_MD5_PASSWORD: i32 = 5;
pub const AUTH_CODE_SCM_CREDS: i32 = 6;
pub const AUTH_CODE_GSS: i32 = 7;
pub const AUTH_CODE_GSS_CONT: i32 = 8;
pub const AUTH_CODE_SSPI: i32 = 9;
pub const AUTH_CODE_SASL: i32 = 10;
pub const AUTH_CODE_SASL_CONTINUE: i32 = 11;
pub const AUTH_CODE_SASL_FINAL: i32 = 12;

#[derive(Debug)]
pub struct AuthenticationOk {}

impl AuthenticationOk {
    pub fn new() -> Self {
        Self {}
    }
}

impl BackendMessage for AuthenticationOk {}

impl Message for AuthenticationOk {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>() {
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
        auth.put_i32(AUTH_CODE_OK);

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
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>() {
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
        auth.put_i32(AUTH_CODE_CLEARTEXT_PASSWORD);

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
    fn new_from_bytes(mut message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len()
            != mem::size_of::<u8>() + mem::size_of::<i32>() * 2 + mem::size_of::<u8>() * 4
        {
            return Err(Error::InvalidBytes);
        }

        let _code = message_bytes.get_u8();
        let _len = message_bytes.get_i32();
        let _type = message_bytes.get_i32();

        // These unwraps are safe because of validation above
        let salt: [u8; 4] = message_bytes.get(0..4).unwrap().try_into().unwrap();

        Ok(Self { salt })
    }

    fn get_bytes(&self) -> BytesMut {
        let mut auth = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() * 2 + mem::size_of::<u8>() * 4,
        );

        auth.put_u8(b'R');
        auth.put_i32(12);
        auth.put_i32(AUTH_CODE_MD5_PASSWORD);
        auth.put_slice(&self.salt);

        return auth;
    }
}

#[derive(Debug)]
pub struct AuthenticationSASL {
    message_bytes: BytesMut,
}

impl AuthenticationSASL {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for AuthenticationSASL {}

impl Message for AuthenticationSASL {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct AuthenticationSASLContinue {
    message_bytes: BytesMut,
}

impl AuthenticationSASLContinue {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for AuthenticationSASLContinue {}

impl Message for AuthenticationSASLContinue {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}

#[derive(Debug)]
pub struct AuthenticationSASLFinal {
    message_bytes: BytesMut,
}

impl AuthenticationSASLFinal {
    pub fn new(message_bytes: BytesMut) -> Self {
        Self { message_bytes }
    }
}

impl BackendMessage for AuthenticationSASLFinal {}

impl Message for AuthenticationSASLFinal {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> BytesMut {
        return self.message_bytes.clone();
    }
}
