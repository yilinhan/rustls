use std::io::Read;
use std::io;
use vecio;

/// This is a byte buffer that is built from a vector
/// of byte vectors.  This avoids extra copies when
/// appending a new byte vector, at the expense of
/// more complexity when reading out.
pub struct ChunkVecBuffer {
  chunks: Vec<Vec<u8>>
}

impl ChunkVecBuffer {
  pub fn new() -> ChunkVecBuffer {
    ChunkVecBuffer {
      chunks: Vec::new()
    }
  }

  pub fn is_empty(&self) -> bool {
    self.chunks.is_empty()
  }

  pub fn append(&mut self, bytes: Vec<u8>) {
    if !bytes.is_empty() {
      self.chunks.push(bytes);
    }
  }

  pub fn take_one(&mut self) -> Vec<u8> {
    self.chunks.remove(0)
  }

  pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    let mut offs = 0;

    while offs < buf.len() && !self.is_empty() {
      let used = try!(self.chunks[0].as_slice().read(&mut buf[offs..]));

      if used == self.chunks[0].len() {
        self.chunks.remove(0);
      } else {
        self.chunks[0] = self.chunks[0].split_off(used);
      }

      offs += used;
    }

    Ok(offs)
  }

  fn consumed(&mut self, mut count: usize) {
    while count > 0 && !self.is_empty() {
      let toplen = self.chunks[0].len();

      if toplen <= count {
        self.chunks.remove(0);
        count -= toplen;
      } else {
        self.chunks[0] = self.chunks[0].split_off(count);
        count = 0;
      }
    }
  }

  pub fn writev_to(&mut self, wrv: &mut vecio::Rawv) -> io::Result<usize> {
    if self.is_empty() {
      return Ok(0);
    }

    let used = {
      let chunksv = self.chunks.iter()
        .map(|v| v.as_slice())
        .collect::<Vec<&[u8]>>();
      try!(wrv.writev(chunksv.as_slice()))
    };
    self.consumed(used);
    return Ok(used);
  }

  pub fn write_to(&mut self, wr: &mut io::Write) -> io::Result<usize> {
    if self.is_empty() {
      return Ok(0);
    }

    let used = try!(wr.write(&self.chunks[0]));
    self.consumed(used);
    return Ok(used);
  }
}
