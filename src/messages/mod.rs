use std::mem;

use bytes::BytesMut;
use memchr::memchr;

use crate::errors::Error;

#[derive(Debug)]
pub struct Buffer {
    buffer: BytesMut,
    idx: usize,
}

impl Buffer {
    pub fn new(buffer: BytesMut) -> Self {
        Self { buffer, idx: 0 }
    }

    pub fn slice(&self) -> &[u8] {
        &self.buffer[self.idx..]
    }

    pub fn is_empty(&self) -> bool {
        self.slice().is_empty()
    }

    pub fn read_string(&mut self) -> Result<String, Error> {
        match memchr(0, self.slice()) {
            Some(pos) => {
                let start = self.idx;
                let end = start + pos;
                let cstr = self.buffer.get(start..end).unwrap(); // known size
                self.idx = end + 1;
                Ok(String::from_utf8_lossy(cstr).to_string())
            }
            None => Err(Error::UnexpectedEof),
        }
    }

    fn read_by_size(&mut self, size: usize) -> Result<&[u8], Error> {
        let start = self.idx;
        let end = start + size;
        match self.buffer.get(start..end) {
            Some(s) => {
                self.idx = end;
                Ok(s)
            }
            None => Err(Error::UnexpectedEof),
        }
    }

    pub fn read_i32(&mut self) -> Result<i32, Error> {
        let buf: &[u8; 4] = match self.read_by_size(mem::size_of::<i32>())?.try_into() {
            Ok(buf) => buf,
            Err(e) => panic!("{:?}", e), // TODO: handle error
        };

        Ok(i32::from_be_bytes(*buf))
    }

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let buf: &[u8; 1] = match self.read_by_size(mem::size_of::<u8>())?.try_into() {
            Ok(buf) => buf,
            Err(e) => panic!("{:?}", e), // TODO: handle error
        };

        Ok(buf[0])
    }

    pub fn read_byte_array(&mut self, size: usize) -> Result<&[u8], Error> {
        let buf: &[u8] = match self.read_by_size(size) {
            Ok(buf) => buf,
            Err(e) => panic!("{:?}", e), // TODO: handle
        };

        Ok(buf)
    }
}

pub trait Message {
    fn new_from_bytes(message_bytes: BytesMut) -> Result<Self, Error>
    where
        Self: Sized;

    fn get_bytes(&self) -> &BytesMut;
}

pub mod backend;
pub mod frontend;
