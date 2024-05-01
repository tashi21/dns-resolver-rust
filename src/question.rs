use super::{errors::Result, raw_packet::RawPacket};

#[derive(Debug, Clone)]
pub enum QueryType {
    Unknown(u16),
    A,
    NS,
    Cname,
    MX,
    Aaaa,
}

impl QueryType {
    pub fn from_num(rec_type: u16) -> Self {
        match rec_type {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::Cname,
            15 => Self::MX,
            28 => Self::Aaaa,
            _ => Self::Unknown(rec_type),
        }
    }

    pub fn to_num(&self) -> u16 {
        match self {
            Self::Unknown(num) => *num,
            Self::A => 1,
            Self::NS => 2,
            Self::Cname => 5,
            Self::MX => 15,
            Self::Aaaa => 28,
        }
    }
}

#[derive(Debug)]
/// The Question Section stories information about the query
pub struct Question {
    /// The domain name being queried
    pub name: String, // variable bit length
    /// The record type requested for the query
    pub query_type: QueryType, // 16 bits
    /// The record class, in practice always 1
    pub class: u16, // 16 bits
}

impl Question {
    /// A new empty question
    pub fn new() -> Self {
        Question {
            name: String::new(),
            query_type: QueryType::Unknown(0),
            class: 0,
        }
    }

    /// Parse the question query from the given buffer
    pub fn parse(&mut self, buf: &mut RawPacket) -> Result<()> {
        buf.read_query_name(&mut self.name)?;
        self.query_type = QueryType::from_num(buf.read_u16()?);
        self.class = buf.read_u16()?;

        Ok(())
    }

    /// Write a question into a RawPacket
    pub fn write(&self, buf: &mut RawPacket) -> Result<()> {
        buf.write_query_name(&self.name)?;
        buf.write_u16(self.query_type.to_num())?;
        buf.write_u16(self.class)?;

        Ok(())
    }
}
