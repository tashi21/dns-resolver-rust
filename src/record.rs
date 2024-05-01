use std::net::{Ipv4Addr, Ipv6Addr};

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
    NS {
        preamble: RecordPreamble,
        name: String,
    },
    Cname {
        preamble: RecordPreamble,
        name: String,
    },
    MX {
        preamble: RecordPreamble,
        priority: u16,
        name: String,
    },
    Aaaa {
        preamble: RecordPreamble,
        ip: Ipv6Addr,
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

            QueryType::A => Ok(Record::A {
                preamble,
                ip: Ipv4Addr::new(
                    buf.read_u8()?,
                    buf.read_u8()?,
                    buf.read_u8()?,
                    buf.read_u8()?,
                ),
            }),

            QueryType::NS => {
                let mut name = String::new();
                buf.read_query_name(&mut name)?;

                Ok(Record::NS { preamble, name })
            }

            QueryType::Cname => {
                let mut name = String::new();
                buf.read_query_name(&mut name)?;

                Ok(Record::Cname { preamble, name })
            }

            QueryType::MX => {
                let priority = buf.read_u16()?;
                let mut name = String::new();
                buf.read_query_name(&mut name)?;

                Ok(Record::MX {
                    preamble,
                    priority,
                    name,
                })
            }

            QueryType::Aaaa => Ok(Record::Aaaa {
                preamble,
                ip: Ipv6Addr::new(
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                ),
            }),
        }
    }

    /// Write a record into a RawPacket
    pub fn write(&self, buf: &mut RawPacket) -> Result<()> {
        match self {
            Self::A { preamble, ip } => {
                Self::write_preamble(preamble, buf)?;

                for octet in ip.octets() {
                    buf.write_u8(octet)?;
                }

                Ok(())
            }

            Self::NS { preamble, name } => {
                let len_pos = Self::write_preamble(preamble, buf)?;
                buf.write_query_name(name)?;
                buf.set_u16(len_pos, (buf.cursor() - (len_pos + 2)) as u16)?;

                Ok(())
            }

            Self::Cname { preamble, name } => {
                let len_pos = Self::write_preamble(preamble, buf)?;
                buf.write_query_name(name)?;
                buf.set_u16(len_pos, (buf.cursor() - (len_pos + 2)) as u16)?;

                Ok(())
            }

            Self::MX {
                preamble,
                priority,
                name,
            } => {
                let len_pos = Self::write_preamble(preamble, buf)?;
                buf.write_u16(*priority)?;
                buf.write_query_name(name)?;
                buf.set_u16(len_pos, (buf.cursor() - (len_pos + 2)) as u16)?;

                Ok(())
            }

            Self::Aaaa { preamble, ip } => {
                Self::write_preamble(preamble, buf)?;

                for segment in ip.segments() {
                    buf.write_u16(segment)?;
                }

                Ok(())
            }

            Self::Unknown { preamble, data } => {
                Self::write_preamble(preamble, buf)?;

                for byte in data {
                    buf.write_u8(*byte)?;
                }

                Ok(())
            }
        }
    }

    /// Write a record into a RawPacket and return the position where the length was written
    fn write_preamble(preamble: &RecordPreamble, buf: &mut RawPacket) -> Result<usize> {
        buf.write_query_name(&preamble.name)?;
        buf.write_u16(preamble.query_type.to_num())?;
        buf.write_u16(preamble.class)?;
        buf.write_u32(preamble.ttl)?;
        let len_pos = buf.cursor();
        buf.write_u16(preamble.len)?;

        Ok(len_pos)
    }
}
