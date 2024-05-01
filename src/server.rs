use super::{
    dns_packet::DNSPacket,
    errors::{Errors::IOErr, Result},
    header::ResponseCode::{Formerr, Servfail},
    question::{QueryType, Question},
    raw_packet::RawPacket,
};

use rand::{thread_rng, Rng};
use std::net::{Ipv4Addr, UdpSocket};

const UDP_PORT: u16 = 53; // Default UDP port for DNS Packets
const DNS_RESOLVER_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8); // Google's  public DNS server
const LOOKUP_SERVER: (Ipv4Addr, u16) = (DNS_RESOLVER_IP, UDP_PORT);

const DNS_SERVER_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const SERVER: (Ipv4Addr, u16) = (DNS_SERVER_IP, UDP_PORT);

/// Perform a lookup for the given domain and requested record type
pub fn lookup(query: &str, query_type: QueryType) -> Result<DNSPacket> {
    // bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(SERVER).map_err(IOErr)?;

    // build query packet
    let mut query_packet = DNSPacket::new();
    query_packet.header.id = thread_rng().gen(); // generate random transaction ID
    query_packet.header.qd_count = 1; // always one query
    query_packet.header.rd = true; // always desire recursion

    // create the question record
    let mut que = Question::new();
    que.name = String::from(query);
    que.query_type = query_type;
    que.class = 1; // always 1 in practice
    query_packet.question_sec.push(que);

    // write query_packet to buffer
    let mut query_buf = RawPacket::new();
    query_packet.write(&mut query_buf)?;

    // send query packet to DNS resolver
    socket
        .send_to(&query_buf.buf[0..query_buf.cursor()], LOOKUP_SERVER)
        .map_err(IOErr)?;

    // buffer to store response packet
    let mut res_buf = RawPacket::new();
    // write received data into buffer
    socket.recv_from(&mut res_buf.buf).map_err(IOErr)?;

    // parse response packet into DNS Packet
    let mut res_packet = DNSPacket::new();
    res_packet.parse(&mut res_buf)?;

    Ok(res_packet)
}

/// Handle recursive lookups if required
fn handle_query(socket: &UdpSocket) -> Result<()> {
    // create buffer to receive query packet
    let mut query_buf = RawPacket::new();
    let (_, query_src) = socket.recv_from(&mut query_buf.buf).map_err(IOErr)?;

    // parse buffer into DNS Packet
    let mut query_packet = DNSPacket::new();
    query_packet.parse(&mut query_buf)?;

    // Create and initialize the response packet
    let mut res_packet = DNSPacket::new();
    res_packet.header.id = query_packet.header.id; // same ID as query
    res_packet.header.rd = true;
    res_packet.header.ra = true;
    res_packet.header.qr = true;

    // expect 1 question only
    if let Some(que) = query_packet.question_sec.pop() {
        if let Ok(result) = lookup(&que.name, que.query_type) {
            res_packet.question_sec.push(que); // add question to response packet also
            res_packet.header.rcode = result.header.rcode; // same response code as query

            for rec in result.answer_sec {
                res_packet.answer_sec.push(rec);
            }

            for rec in result.authority_sec {
                res_packet.authority_sec.push(rec);
            }

            for rec in result.additional_sec {
                res_packet.additional_sec.push(rec);
            }
        } else {
            res_packet.header.rcode = Servfail;
        }
    }
    // no question found
    else {
        res_packet.header.rcode = Formerr;
    }

    // encode response packet into bytes
    let mut res_buf = RawPacket::new();
    res_packet.write(&mut res_buf)?;
    let len = res_buf.cursor();
    let data = res_buf.get_bytes_from(0, len - 1)?;

    socket.send_to(data, query_src)?;

    Ok(())
}
