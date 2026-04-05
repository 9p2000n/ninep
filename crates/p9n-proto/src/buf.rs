//! Growable byte buffer with little-endian 9P wire primitives.

use crate::error::WireError;
use crate::wire::Qid;

type Result<T> = std::result::Result<T, WireError>;

/// A buffer for marshalling/unmarshalling 9P messages.
pub struct Buf {
    data: Vec<u8>,
    pos: usize,
}

impl Buf {
    /// Create a new write buffer.
    pub fn new(cap: usize) -> Self {
        Self { data: Vec::with_capacity(cap), pos: 0 }
    }

    /// Wrap existing data for reading (takes ownership, zero-copy).
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    /// Wrap a mutable Vec for writing (reuses allocation, zero-copy).
    /// The Vec is cleared before use.
    pub fn from_vec(data: &mut Vec<u8>) -> Self {
        let mut v = std::mem::take(data);
        v.clear();
        Self { data: v, pos: 0 }
    }

    /// Consume the Buf and return the inner Vec (zero-copy).
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    /// Returns the written data.
    pub fn as_bytes(&self) -> &[u8] { &self.data }

    /// Returns the number of bytes written.
    pub fn len(&self) -> usize { self.data.len() }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool { self.data.is_empty() }

    /// Current read position.
    pub fn pos(&self) -> usize { self.pos }

    /// Resets the buffer.
    pub fn reset(&mut self) { self.data.clear(); self.pos = 0; }

    /// Remaining bytes available for reading.
    pub fn remaining(&self) -> usize { self.data.len().saturating_sub(self.pos) }

    // ── Write operations ──

    pub fn put_u8(&mut self, v: u8) { self.data.push(v); }

    pub fn put_u16(&mut self, v: u16) { self.data.extend_from_slice(&v.to_le_bytes()); }

    pub fn put_u32(&mut self, v: u32) { self.data.extend_from_slice(&v.to_le_bytes()); }

    pub fn put_u64(&mut self, v: u64) { self.data.extend_from_slice(&v.to_le_bytes()); }

    /// Write a length-prefixed string: len[2] + UTF-8 bytes.
    pub fn put_str(&mut self, s: &str) {
        self.put_u16(s.len() as u16);
        self.data.extend_from_slice(s.as_bytes());
    }

    /// Write a length-prefixed data blob: len[4] + bytes.
    pub fn put_data(&mut self, d: &[u8]) {
        self.put_u32(d.len() as u32);
        self.data.extend_from_slice(d);
    }

    /// Write raw bytes.
    pub fn put_bytes(&mut self, d: &[u8]) { self.data.extend_from_slice(d); }

    /// Write a QID (13 bytes).
    pub fn put_qid(&mut self, q: &Qid) {
        self.put_u8(q.qtype);
        self.put_u32(q.version);
        self.put_u64(q.path);
    }

    /// Patch a u32 at a specific offset (for size field).
    pub fn patch_u32(&mut self, off: usize, v: u32) {
        self.data[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    // ── Read operations ──

    fn check(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            Err(WireError::ShortBuffer { need: n, have: self.remaining() })
        } else {
            Ok(())
        }
    }

    pub fn get_u8(&mut self) -> Result<u8> {
        self.check(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn get_u16(&mut self) -> Result<u16> {
        self.check(2)?;
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn get_u32(&mut self) -> Result<u32> {
        self.check(4)?;
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub fn get_u64(&mut self) -> Result<u64> {
        self.check(8)?;
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    pub fn get_str(&mut self) -> Result<String> {
        let slen = self.get_u16()? as usize;
        self.check(slen)?;
        let s = String::from_utf8_lossy(&self.data[self.pos..self.pos + slen]).into_owned();
        self.pos += slen;
        Ok(s)
    }

    pub fn get_data(&mut self) -> Result<Vec<u8>> {
        let n = self.get_u32()? as usize;
        self.check(n)?;
        let d = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(d)
    }

    pub fn get_fixed(&mut self, n: usize) -> Result<Vec<u8>> {
        self.check(n)?;
        let d = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(d)
    }

    pub fn get_qid(&mut self) -> Result<Qid> {
        Ok(Qid {
            qtype: self.get_u8()?,
            version: self.get_u32()?,
            path: self.get_u64()?,
        })
    }
}
