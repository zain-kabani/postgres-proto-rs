use bytes::{Buf, BufMut, BytesMut};
use std::{
    io::{Cursor, Read},
    mem,
};

use crate::messages::{BytesMutReader, Error, Message};

//----------------------------------------------------------------
// Backend Messages

#[derive(Debug)]
pub enum BackendMessageType {
    AuthenticationCleartextPassword(AuthenticationCleartextPassword),
    AuthenticationMd5Password(AuthenticationMD5Password),
    AuthenticationOk(AuthenticationOk),
    AuthenticationSASL(AuthenticationSASL),
    AuthenticationSASLContinue(AuthenticationSASLContinue),
    AuthenticationSASLFinal(AuthenticationSASLFinal),
    BackendKeyData(BackendKeyData),
    BindComplete(BindComplete),
    CloseComplete(CloseComplete),
    CommandComplete(CommandComplete),
    CopyData(CopyData),
    CopyDone(CopyDone),
    CopyInResponse(CopyInResponse),
    CopyOutResponse(CopyOutResponse),
    DataRow(DataRow),
    EmptyQueryResponse(EmptyQueryResponse),
    ErrorResponse(ErrorResponse),
    NoData(NoData),
    NoticeResponse(NoticeResponse),
    NotificationResponse(NotificationResponse),
    ParameterDescription(ParameterDescription),
    ParameterStatus(ParameterStatus),
    ParseComplete(ParseComplete),
    PortalSuspended(PortalSuspended),
    ReadyForQuery(ReadyForQuery),
    RowDescription(RowDescription),
    FunctionCallResponse(FunctionCallResponse),
    CopyBothResponse(CopyBothResponse),
}

impl BackendMessageType {
    pub fn get_bytes(&self) -> &BytesMut {
        match self {
            Self::AuthenticationCleartextPassword(ct_password) => ct_password.get_bytes(),
            Self::AuthenticationMd5Password(md5_password) => md5_password.get_bytes(),
            Self::AuthenticationOk(auth_ok) => auth_ok.get_bytes(),
            Self::AuthenticationSASL(sasl) => sasl.get_bytes(),
            Self::AuthenticationSASLContinue(sasl_cont) => sasl_cont.get_bytes(),
            Self::AuthenticationSASLFinal(sasl_final) => sasl_final.get_bytes(),
            Self::BackendKeyData(data) => data.get_bytes(),
            Self::BindComplete(bind_complete) => bind_complete.get_bytes(),
            Self::CloseComplete(close_complete) => close_complete.get_bytes(),
            Self::CommandComplete(command_complete) => command_complete.get_bytes(),
            Self::CopyData(copy_data) => copy_data.get_bytes(),
            Self::CopyDone(copy_done) => copy_done.get_bytes(),
            Self::CopyInResponse(copy_in_response) => copy_in_response.get_bytes(),
            Self::CopyOutResponse(copy_out_response) => copy_out_response.get_bytes(),
            Self::DataRow(row_data) => row_data.get_bytes(),
            Self::EmptyQueryResponse(empty_query_response) => empty_query_response.get_bytes(),
            Self::ErrorResponse(error_response) => error_response.get_bytes(),
            Self::NoData(no_data) => no_data.get_bytes(),
            Self::NoticeResponse(notice_response) => notice_response.get_bytes(),
            Self::NotificationResponse(notif_resp) => notif_resp.get_bytes(),
            Self::ParameterDescription(param_desc) => param_desc.get_bytes(),
            Self::ParameterStatus(parameter_status) => parameter_status.get_bytes(),
            Self::ParseComplete(parse_complete) => parse_complete.get_bytes(),
            Self::PortalSuspended(portal_suspended) => portal_suspended.get_bytes(),
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
                    AUTH_CODE_OK => {
                        let auth_ok = AuthenticationOk::new_from_bytes(message_bytes)?;
                        Ok(Self::AuthenticationOk(auth_ok))
                    }
                    AUTH_CODE_CLEARTEXT_PASSWORD => {
                        let cleartext_password =
                            AuthenticationCleartextPassword::new_from_bytes(message_bytes)?;
                        Ok(Self::AuthenticationCleartextPassword(cleartext_password))
                    }
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
            '1' => {
                let parse_complete = ParseComplete::new_from_bytes(message_bytes)?;
                Ok(Self::ParseComplete(parse_complete))
            }
            '2' => {
                let bind_complete = BindComplete::new_from_bytes(message_bytes)?;
                Ok(Self::BindComplete(bind_complete))
            }
            '3' => {
                let close_complete = CloseComplete::new_from_bytes(message_bytes)?;
                Ok(Self::CloseComplete(close_complete))
            }
            'A' => {
                let notification_response = NotificationResponse::new_from_bytes(message_bytes)?;
                Ok(Self::NotificationResponse(notification_response))
            }
            'c' => {
                let copy_done = CopyDone::new_from_bytes(message_bytes)?;
                Ok(Self::CopyDone(copy_done))
            }
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
            'I' => {
                let empty_query_response = EmptyQueryResponse::new_from_bytes(message_bytes)?;
                Ok(Self::EmptyQueryResponse(empty_query_response))
            }
            'n' => {
                let no_data = NoData::new_from_bytes(message_bytes)?;
                Ok(Self::NoData(no_data))
            }
            'N' => {
                let notice_response = NoticeResponse::new_from_bytes(message_bytes)?;
                Ok(Self::NoticeResponse(notice_response))
            }
            's' => {
                let portal_suspended = PortalSuspended::new_from_bytes(message_bytes)?;
                Ok(Self::PortalSuspended(portal_suspended))
            }
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
pub struct ParseComplete {
    message_bytes: BytesMut,
}

impl ParseComplete {
    pub fn new() -> Self {
        let mut message_bytes =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        message_bytes.put_u8(b'1');
        message_bytes.put_i32(4);

        Self { message_bytes }
    }
}

impl BackendMessage for ParseComplete {}

impl Message for ParseComplete {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct BindComplete {
    message_bytes: BytesMut,
}

impl BindComplete {
    pub fn new() -> Self {
        let mut message_bytes =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        message_bytes.put_u8(b'2');
        message_bytes.put_i32(4);

        Self { message_bytes }
    }
}

impl BackendMessage for BindComplete {}

impl Message for BindComplete {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct CloseComplete {
    message_bytes: BytesMut,
}

impl CloseComplete {
    pub fn new() -> Self {
        let mut message_bytes =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        message_bytes.put_u8(b'3');
        message_bytes.put_i32(4);

        Self { message_bytes }
    }
}

impl BackendMessage for CloseComplete {}

impl Message for CloseComplete {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct CopyDone {
    message_bytes: BytesMut,
}

impl CopyDone {
    pub fn new() -> Self {
        let mut message_bytes =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        message_bytes.put_u8(b'c');
        message_bytes.put_i32(4);
        Self { message_bytes }
    }
}

impl BackendMessage for CopyDone {}

impl Message for CopyDone {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct CommandComplete {
    message_bytes: BytesMut,
}

pub struct CommandCompleteParams {
    pub command_tag: String,
}

impl CommandComplete {
    pub fn new(command_tag: String) -> Self {
        let mut message_bytes = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<u8>(),
        );

        let msg_len = (command_tag.len() + 1 + mem::size_of::<i32>()) as i32;

        message_bytes.put_u8(b'C');
        message_bytes.put_i32(msg_len);
        message_bytes.put(&command_tag.as_bytes()[..]);
        message_bytes.put_u8(0);

        Self { message_bytes }
    }

    pub fn get_params(&self) -> CommandCompleteParams {
        let mut cursor = Cursor::new(&self.message_bytes);

        let _code = cursor.get_u8();
        let _len = cursor.get_i32() as usize;

        let command_tag = cursor.read_string().unwrap();

        CommandCompleteParams { command_tag }
    }
}

impl BackendMessage for CommandComplete {}

impl Message for CommandComplete {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct EmptyQueryResponse {
    message_bytes: BytesMut,
}

impl EmptyQueryResponse {
    pub fn new() -> Self {
        let mut message_bytes =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        message_bytes.put_u8(b'I');
        message_bytes.put_i32(4);
        Self { message_bytes }
    }
}

impl BackendMessage for EmptyQueryResponse {}

impl Message for EmptyQueryResponse {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct BackendKeyData {
    message_bytes: BytesMut,
}

pub struct BackendKeyDataParams {
    pub process_id: i32,
    pub secret_key: i32,
}

impl BackendKeyData {
    pub fn new(process_id: i32, secret_key: i32) -> Self {
        let mut message_bytes = BytesMut::with_capacity(
            mem::size_of::<u8>()
                + mem::size_of::<i32>()
                + mem::size_of::<i32>()
                + mem::size_of::<i32>(),
        );

        message_bytes.put_u8(b'K');
        message_bytes.put_i32(12);
        message_bytes.put_i32(process_id);
        message_bytes.put_i32(secret_key);

        Self { message_bytes }
    }

    pub fn get_params(&self) -> BackendKeyDataParams {
        let mut cursor = Cursor::new(&self.message_bytes);

        let _code = cursor.get_u8();
        let _len = cursor.get_i32();
        let process_id = cursor.get_i32();
        let secret_key = cursor.get_i32();

        BackendKeyDataParams {
            process_id,
            secret_key,
        }
    }
}

impl BackendMessage for BackendKeyData {}

impl Message for BackendKeyData {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len()
            != mem::size_of::<u8>()
                + mem::size_of::<i32>()
                + mem::size_of::<i32>()
                + mem::size_of::<i32>()
        {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct NoData {
    message_bytes: BytesMut,
}

impl NoData {
    pub fn new() -> Self {
        let mut message_bytes =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        message_bytes.put_u8(b'n');
        message_bytes.put_i32(4);

        Self { message_bytes }
    }
}

impl BackendMessage for NoData {}

impl Message for NoData {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len() != mem::size_of::<u8>() + mem::size_of::<i32>() {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct PortalSuspended {
    message_bytes: BytesMut,
}

impl PortalSuspended {
    pub fn new() -> Self {
        let mut message_bytes =
            BytesMut::with_capacity(mem::size_of::<u8>() + mem::size_of::<i32>());

        message_bytes.put_u8(b's');
        message_bytes.put_i32(4);

        Self { message_bytes }
    }
}

impl BackendMessage for PortalSuspended {}

impl Message for PortalSuspended {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct ReadyForQuery {
    message_bytes: BytesMut,
}

pub struct ReadyForQueryParams {
    pub tx_status: u8,
}

impl ReadyForQuery {
    pub fn new(tx_status: u8) -> Self {
        let mut message_bytes = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<u8>(),
        );
        message_bytes.put_u8(b'Z');
        message_bytes.put_i32(5);
        message_bytes.put_u8(tx_status);

        Self { message_bytes }
    }

    pub fn get_params(&self) -> ReadyForQueryParams {
        let mut cursor = Cursor::new(&self.message_bytes);

        let _code = cursor.get_u8();
        let _len = cursor.get_i32();
        let tx_status = cursor.get_u8(); // TODO: Add validation

        ReadyForQueryParams { tx_status }
    }
}

impl BackendMessage for ReadyForQuery {}

impl Message for ReadyForQuery {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len()
            != mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<u8>()
        {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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
pub struct AuthenticationOk {
    message_bytes: BytesMut,
}

impl AuthenticationOk {
    pub fn new() -> Self {
        let mut message_bytes = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>(),
        );

        message_bytes.put_u8(b'R');
        message_bytes.put_i32(8);
        message_bytes.put_i32(AUTH_CODE_OK);

        Self { message_bytes }
    }
}

impl BackendMessage for AuthenticationOk {}

impl Message for AuthenticationOk {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len()
            != mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>()
        {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct AuthenticationCleartextPassword {
    message_bytes: BytesMut,
}

impl AuthenticationCleartextPassword {
    pub fn new() -> Self {
        let mut message_bytes = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>(),
        );

        message_bytes.put_u8(b'R');
        message_bytes.put_i32(8);
        message_bytes.put_i32(AUTH_CODE_CLEARTEXT_PASSWORD);

        Self { message_bytes }
    }
}

impl BackendMessage for AuthenticationCleartextPassword {}

impl Message for AuthenticationCleartextPassword {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len()
            != mem::size_of::<u8>() + mem::size_of::<i32>() + mem::size_of::<i32>()
        {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}

#[derive(Debug)]
pub struct AuthenticationMD5Password {
    message_bytes: BytesMut,
}

pub struct AuthenticationMD5PasswordParams {
    pub salt: [u8; 4],
}

impl AuthenticationMD5Password {
    pub fn new(salt: [u8; 4]) -> Self {
        let mut message_bytes = BytesMut::with_capacity(
            mem::size_of::<u8>() + mem::size_of::<i32>() * 2 + mem::size_of::<u8>() * 4,
        );

        message_bytes.put_u8(b'R');
        message_bytes.put_i32(12);
        message_bytes.put_i32(AUTH_CODE_MD5_PASSWORD);
        message_bytes.put_slice(&salt);

        Self { message_bytes }
    }

    pub fn get_params(&self) -> AuthenticationMD5PasswordParams {
        let mut cursor = Cursor::new(&self.message_bytes);

        let _code = cursor.get_u8();
        let _len = cursor.get_i32();
        let _type = cursor.get_i32();

        let mut salt = [0; 4];
        cursor.read_exact(&mut salt).unwrap();

        AuthenticationMD5PasswordParams { salt }
    }
}

impl BackendMessage for AuthenticationMD5Password {}

impl Message for AuthenticationMD5Password {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error> {
        if message_bytes.len()
            != mem::size_of::<u8>() + mem::size_of::<i32>() * 2 + mem::size_of::<u8>() * 4
        {
            return Err(Error::InvalidBytes);
        }

        Ok(Self { message_bytes })
    }

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
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

    fn get_bytes(&self) -> &BytesMut {
        return &self.message_bytes;
    }
}
