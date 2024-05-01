mod dns_packet;
mod errors;
mod header;
mod question;
mod raw_packet;
mod record;
mod server;

use errors::Result;
use question::QueryType;
use server::lookup;

fn main() -> Result<()> {
    let _packet = lookup("", QueryType::A)?;

    Ok(())
}
