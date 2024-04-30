use std::net::Ipv4Addr;

use super::{errors::Result, question::QueryType, raw_packet::RawPacket};

#[derive(Debug)]
/// Record Preamble that is common for all different types of records
pub struct RecordPreamble {
    /// Domain name
    name: String, // variable number of bits
    /// Record type
    query_type: QueryType, // 16 bits
    /// The class, in practice always 1
    class: u16, // 16 bits
    /// How long a record can be cached before it has to be queried again
    ttl: u32, // 32 bits
    /// Length of record specific data
    len: u16, // 16 bits
}

#[derive(Debug)]
/// Information about the record being sent
pub enum Record {
    Unknown {
        preamble: RecordPreamble,
        data: Vec<u8>,
    },
    A {
        preamble: RecordPreamble,
        ip: Ipv4Addr,
    },
}

impl Record {
    pub fn parse(buf: &mut RawPacket) -> Result<Record> {
        let mut name = String::new();
        buf.read_query_name(&mut name)?;

        let query_type_num = buf.read_u16()?;
        let class = buf.read_u16()?;
        let ttl = buf.read_u32()?;
        let len = buf.read_u16()?;

        let preamble = RecordPreamble {
            name,
            query_type: QueryType::from_num(query_type_num),
            class,
            ttl,
            len,
        };

        match QueryType::from_num(query_type_num) {
            QueryType::Unknown(_) => {
                let pos = buf.cursor();
                buf.step(len as usize)?; // move buffer cursor ahead to adjust for future reads
                Ok(Record::Unknown {
                    preamble,
                    data: buf.get_bytes_from(pos, pos + len as usize - 1)?.into(),
                })
            }
            QueryType::A => {
                let mask = 0b1111_1111;
                let raw_address = buf.read_u32()?;
                let address = Ipv4Addr::new(
                    ((raw_address >> 24) & mask) as u8,
                    ((raw_address >> 16) & mask) as u8,
                    ((raw_address >> 8) & mask) as u8,
                    (raw_address & mask) as u8,
                );

                Ok(Record::A {
                    preamble,
                    ip: address,
                })
            }
        }
    }
}
