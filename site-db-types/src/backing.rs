// SPDX-License-Identifier: MPL-2.0

use std::{fs, io};

pub enum LenError {
    UnknownLen(io::Error),
}

pub enum ReadError {
    Seek(io::Error),
    ReadExact(io::Error),
}

pub enum WriteError {
    Seek(io::Error),
    WriteAll(io::Error),
}

pub trait Backing {
    fn len(&self) -> Result<u64, LenError>;

    fn read(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), ReadError>;

    fn write(&mut self, addr: u64, buf: &[u8]) -> Result<(), WriteError>;

    fn flush(&mut self);
}

impl Backing for fs::File {
    fn len(&self) -> Result<u64, LenError> {
        self
            .metadata()
            .map_err(LenError::UnknownLen)
            .map(|meta| meta.len())
    }

    fn read(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        use io::Read as _;

        seek_file(self, addr).map_err(ReadError::Seek)?;

        self.read_exact(buf).map_err(ReadError::ReadExact)
    }

    fn write(&mut self, addr: u64, buf: &[u8]) -> Result<(), WriteError> {
        use io::Write as _;

        seek_file(self, addr).map_err(WriteError::Seek)?;

        self.write_all(buf).map_err(WriteError::WriteAll)
    }

    fn flush(&mut self) {
        // TODO: should we catch errors?
        let _ = <Self as io::Write>::flush(self);
    }
}

fn seek_file(file: &mut fs::File, addr: u64) -> io::Result<()> {
    use io::Seek as _;

    file.seek(io::SeekFrom::Start(addr)).map(|_| ())
}
