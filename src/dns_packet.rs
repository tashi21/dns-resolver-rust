use crate::raw_packet::RawPacket;

use super::{errors::Result, header::Header, question::Question, record::Record};

/// The entire DNS Packet
pub struct DNSPacket {
    /// Information about the query or response
    pub header: Header,
    /// In practice a single query indicating the domain and record type of interest
    pub question_sec: Vec<Question>,
    /// Relevant records of the requested type
    pub answer_sec: Vec<Record>,
    /// List of name server records to resole queries recursively
    pub authority_sec: Vec<Record>,
    /// Additional records that may be useful
    pub additional_sec: Vec<Record>,
}

impl DNSPacket {
    /// Create a new empty DNS Packet
    pub fn new() -> Self {
        DNSPacket {
            header: Header::new(),
            question_sec: Vec::new(),
            answer_sec: Vec::new(),
            authority_sec: Vec::new(),
            additional_sec: Vec::new(),
        }
    }

    pub fn parse(&mut self, buf: &mut RawPacket) -> Result<()> {
        self.header.parse(buf)?;
        for _ in 0..self.header.qd_count {
            let mut question = Question::new();
            question.parse(buf)?;
            self.question_sec.push(question);
        }

        for _ in 0..self.header.an_count {
            let record = Record::parse(buf)?;
            self.answer_sec.push(record);
        }

        for _ in 0..self.header.ns_count {
            let record = Record::parse(buf)?;
            self.authority_sec.push(record);
        }

        for _ in 0..self.header.ar_count {
            let record = Record::parse(buf)?;
            self.additional_sec.push(record);
        }

        Ok(())
    }
}
