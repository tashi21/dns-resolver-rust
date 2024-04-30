use super::{errors::Result, raw_packet::RawPacket};

#[derive(Debug)]
/// Represent the response code of the packet
enum ResponseCode {
    Noerror,
    Former,
    Servfail,
    Nxdomain,
    Notimp,
    Refused,
}

impl ResponseCode {
    fn from_num(code: u8) -> Self {
        match code {
            1 => Self::Former,
            2 => Self::Servfail,
            3 => Self::Nxdomain,
            4 => Self::Notimp,
            5 => Self::Refused,
            _ => Self::Noerror,
        }
    }

    fn to_num(&self) -> u8 {
        match self {
            Self::Noerror => 0,
            Self::Former => 1,
            Self::Servfail => 2,
            Self::Nxdomain => 3,
            Self::Notimp => 4,
            Self::Refused => 5,
        }
    }
}

#[derive(Debug)]
/// DNS Header stores meta information about the packet
pub struct Header {
    /// Random identifier assigned to query packets. Response packets must reply wth same id
    id: u16, // 16 bits
    /// If packet is a query
    qr: bool, // 1 bit
    /// Operation Code, usually always 0
    op_code: u8, // 4 bits
    /// If responding server is authoritative
    aa: bool, // 1 bit
    /// If it is a truncated message (original packet exceeds 512 bytes)
    tc: bool, // 1 bit
    /// If server should attempt recursive resolution
    rd: bool, // 1 bit
    /// If server can satisfy recursive queries
    ra: bool, // 1 bit
    /// Used for DNSSEC queries
    z: u8, // 3 bits
    /// Response code
    rcode: ResponseCode, // 4 bits
    /// Number of entries in Question Section
    pub qd_count: u16, // 16 bits
    /// Number of entries in Answer Section
    pub an_count: u16, // 16 bits
    /// Number of entries in Authority Section
    pub ns_count: u16, // 16 bits
    /// Number of entries in Additional Section
    pub ar_count: u16, // 16 bits
}

impl Header {
    /// A new empty header
    pub fn new() -> Self {
        Self {
            id: 0,
            qr: false,
            op_code: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: ResponseCode::Noerror,
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }

    /// Parse the header from the given buffer
    pub fn parse(&mut self, buf: &mut RawPacket) -> Result<()> {
        self.id = buf.read_u16()?;

        let byte1 = buf.read_u8()?;
        self.qr = byte1 & 0b1000_0000 > 0;
        self.op_code = (byte1 & 0b0111_1000) >> 3;
        self.aa = byte1 & 0b0000_0100 > 0;
        self.tc = byte1 & 0b0000_0010 > 0;
        self.rd = byte1 & 0b0000_0001 > 0;

        let byte2 = buf.read_u8()?;
        self.ra = byte2 & 0b1000_0000 > 0;
        self.z = byte2 & 0b0111_0000 >> 4;
        self.rcode = ResponseCode::from_num(byte2 & 0b0000_1111);

        self.qd_count = buf.read_u16()?;
        self.an_count = buf.read_u16()?;
        self.ns_count = buf.read_u16()?;
        self.ar_count = buf.read_u16()?;

        Ok(())
    }
}
