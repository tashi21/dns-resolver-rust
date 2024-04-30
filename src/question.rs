use super::{errors::Result, raw_packet::RawPacket};

#[derive(Debug)]
pub enum QueryType {
    Unknown(u16),
    A,
}

impl QueryType {
    pub fn from_num(rec_type: u16) -> Self {
        match rec_type {
            1 => Self::A,
            _ => Self::Unknown(rec_type),
        }
    }

    fn to_num(&self) -> u16 {
        match self {
            Self::Unknown(num) => *num,
            Self::A => 1,
        }
    }
}

#[derive(Debug)]
/// The Question Section stories information about the query
pub struct Question {
    /// The domain name being queried
    name: String, // variable bit length
    /// The record type requested for the query
    query_type: QueryType, // 16 bits
    /// The record class, in practice always 1
    class: u16, // 16 bits
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

    pub fn parse(&mut self, buf: &mut RawPacket) -> Result<()> {
        buf.read_query_name(&mut self.name)?;
        self.query_type = QueryType::from_num(buf.read_u16()?);
        self.class = buf.read_u16()?;

        Ok(())
    }
}
