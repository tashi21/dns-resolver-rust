mod dns_packet;
mod errors;
mod header;
mod question;
mod raw_packet;
mod record;

use dns_packet::DNSPacket;
use errors::{Errors::FileErr, Result};
use raw_packet::RawPacket;
use std::{fs::File, io::Read};

fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt").map_err(FileErr)?;
    let mut buffer = RawPacket::new();
    let _ = f.read(&mut buffer.buf).map_err(FileErr)?;

    let mut packet = DNSPacket::new();
    packet.parse(&mut buffer)?;

    println!("{:#?}", packet.header);

    for q in packet.question_sec {
        println!("{:#?}", q);
    }
    for rec in packet.answer_sec {
        println!("{:#?}", rec);
    }
    for rec in packet.authority_sec {
        println!("{:#?}", rec);
    }
    for rec in packet.additional_sec {
        println!("{:#?}", rec);
    }

    Ok(())
}
