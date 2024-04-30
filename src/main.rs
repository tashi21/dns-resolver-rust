mod dns_packet;
mod errors;
mod header;
mod question;
mod raw_packet;
mod record;

use dns_packet::DNSPacket;
use errors::{Errors::IOErr, Result};
use question::{QueryType::A, Question};
use raw_packet::RawPacket;
use std::net::UdpSocket;

fn main() -> Result<()> {
    // Using googles public DNS server
    let server = ("8.8.8.8", 53);

    // Bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210)).map_err(IOErr)?;

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut packet = DNSPacket::new();
    packet.header.id = 6666;
    packet.header.qd_count = 1;
    packet.header.rd = true;

    let mut que = Question::new();
    que.name = String::from("www.yahoo.com");
    que.query_type = A;
    que.class = 1;
    packet.question_sec.push(que);

    // Use our new write method to write the packet to a buffer...
    let mut req_buffer = RawPacket::new();
    packet.write(&mut req_buffer)?;

    // ...and send it off to the server using our socket:
    socket
        .send_to(&req_buffer.buf[0..req_buffer.cursor()], server)
        .map_err(IOErr)?;

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer = RawPacket::new();
    socket.recv_from(&mut res_buffer.buf).map_err(IOErr)?;

    // As per the previous section, `DnsPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response.
    let mut res_packet = DNSPacket::new();
    res_packet.parse(&mut res_buffer)?;
    println!("{:#?}", res_packet.header);

    for q in res_packet.question_sec {
        println!("{:#?}", q);
    }
    for rec in res_packet.answer_sec {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authority_sec {
        println!("{:#?}", rec);
    }
    for rec in res_packet.additional_sec {
        println!("{:#?}", rec);
    }

    Ok(())
}
