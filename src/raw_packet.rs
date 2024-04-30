use super::errors::{
    Errors::{BufferEnd, BufferOverflow, JumpCycle, RangeErr},
    Result,
};

const PACKET_SIZE: usize = 512;

/// Representation of a network packet as its bytes
pub struct RawPacket {
    /// Buffer to store the bytes of the packet
    pub buf: [u8; PACKET_SIZE],
    /// Cursor to store current position in buffer
    cursor: usize,
}

impl RawPacket {
    /// Return a new, empty BytePacket
    pub fn new() -> Self {
        RawPacket {
            buf: [0; PACKET_SIZE],
            cursor: 0,
        }
    }

    /// Return current position of cursor
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Increment cursor by step positions
    pub fn step(&mut self, step: usize) -> Result<()> {
        if self.cursor + step >= PACKET_SIZE {
            return Err(BufferOverflow);
        }
        self.cursor += step;

        Ok(())
    }

    /// Move buffer position to given position
    fn seek(&mut self, pos: usize) -> Result<()> {
        if pos >= PACKET_SIZE {
            return Err(BufferOverflow);
        }
        self.cursor = pos;

        Ok(())
    }

    /// Read 1 byte
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.cursor >= PACKET_SIZE {
            return Err(BufferEnd);
        }

        self.cursor += 1; // only read_byte can set cursor to 512 to mark entire buffer as read

        Ok(self.buf[self.cursor - 1])
    }

    /// Read 2 bytes and move cursor ahead
    pub fn read_u16(&mut self) -> Result<u16> {
        let data = ((
            self.read_u8()? as u16) // pad with 8 zeroes
            << 8)  // shift data to left byte
            | (self.read_u8()? as u16); // bitwise or with 0 gives same element so first byte is preserved and second byte becomes the next byte

        Ok(data)
    }

    /// Read 4 bytes
    pub fn read_u32(&mut self) -> Result<u32> {
        let data = ((
            self.read_u16()? as u32) // pad with 16 zeroes
            << 16)  // shift data to left byte
            | (self.read_u16()? as u32); // bitwise or with 0 gives same element so first byte is preserved and second byte becomes the next byte

        Ok(data)
    }

    pub fn read_query_name(&mut self, output: &mut String) -> Result<()> {
        let mut pos = self.cursor; // track position locally as there can be jumps
        let mut delim = ""; // let it be empty string for first iteration

        const MAX_JUMPS: usize = 5; // prevent infinite jump cycle
        let mut jumped = false; // track if one jump has been made
        let mut jumps = 0; // track jumps to prevent infinite jump cycle

        // read one label in one iteration
        // or perform one jump in one iteration
        loop {
            if jumps >= MAX_JUMPS {
                return Err(JumpCycle);
            }

            let len = self.get_byte_at(pos)?; // will always read a length byte at this point

            // 2 MSBs of length are set
            if len & 0b1100_0000 == 0b1100_0000 {
                // parse packet after first jump byte indicators once finished parsing query
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let len_2 = self.get_byte_at(pos + 1)?;
                pos = ((((len as u16)
                    << 8) // shift bits to the 8 MSBs
                    | (len_2 as u16)) // bitwise or to add bits of second byte to the 8 LSBs
                    & 0b0011_1111_1111_1111) as usize; // bitwise and to flip the 2 MSBs and then get only the 14 LSBs

                jumps += 1;
                jumped = true;

                continue;
            }

            pos += 1; // get past length byte

            // all labels have been read
            if len == 0 {
                break;
            }

            output.push_str(delim);
            output.push_str(
                &String::from_utf8_lossy(
                    self.get_bytes_from(pos, pos + len as usize - 1)?, // get label from buffer
                ) // convert to utf-8 string
                .to_lowercase(), // convert to lowercase
            );

            pos += len as usize;
            delim = "."; // dot separator used after first label
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    /// Get byte at given position without updating cursor
    fn get_byte_at(&self, pos: usize) -> Result<u8> {
        if pos >= PACKET_SIZE {
            return Err(BufferOverflow);
        }

        Ok(self.buf[pos])
    }

    /// Get bytes from start to end (inclusive) as a byte slice
    pub fn get_bytes_from(&self, start: usize, end: usize) -> Result<&[u8]> {
        if start > end {
            return Err(RangeErr);
        }
        if start >= PACKET_SIZE || end >= PACKET_SIZE {
            return Err(BufferOverflow);
        }

        Ok(&self.buf[start..=end])
    }
}
