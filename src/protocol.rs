use std::io::{self, Read, Write};
pub const MAX_TRANSFER: usize = 1024 * 1024;
pub const MAX_FRAME: usize = MAX_TRANSFER + 64;
pub const ALLOC: u8 = 1;
pub const READ: u8 = 2;
pub const WRITE: u8 = 3;
pub const FREE: u8 = 4;
pub const VERIFY: u8 = 5;
pub const STATS: u8 = 6;
pub const PING: u8 = 7;

pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    r.read_exact(&mut header)?;
    let n = u32::from_be_bytes(header) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut data = vec![0; n];
    r.read_exact(&mut data)?;
    Ok(data)
}
pub fn write_frame(w: &mut impl Write, code: u8, data: &[u8]) -> io::Result<()> {
    let n = data
        .len()
        .checked_add(1)
        .filter(|n| *n <= MAX_FRAME)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&(n as u32).to_be_bytes())?;
    w.write_all(&[code])?;
    w.write_all(data)?;
    w.flush()
}
pub fn u64_at(data: &[u8], pos: usize) -> u64 {
    u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap())
}
pub fn u32_at(data: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_frame_rejected_before_body_allocation() {
        for n in [0u32, MAX_FRAME as u32 + 1, u32::MAX] {
            assert_eq!(
                read_frame(&mut n.to_be_bytes().as_slice())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut wire = Vec::new();
        write_frame(&mut wire, 7, b"test").unwrap();
        assert_eq!(read_frame(&mut wire.as_slice()).unwrap(), b"\x07test");
        assert!(read_frame(&mut wire[..5].as_ref()).is_err());
    }
}
