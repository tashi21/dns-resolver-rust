use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io, result,
};

#[derive(Debug)]
pub enum Errors {
    BufferEnd,
    BufferOverflow,
    IOErr(io::Error),
    InvalidLabelLen,
    JumpCycle,
    RangeErr,
}
pub type Result<T> = result::Result<T, Errors>;

impl Display for Errors {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferEnd => write!(f, "buffer end reached"),
            Self::BufferOverflow => write!(f, "buffer overflow"),
            Self::IOErr(e) => write!(f, "{}", e),
            Self::InvalidLabelLen => write!(f, "label exceeds 63 characters"),
            Self::RangeErr => write!(f, "invalid range"),
            Self::JumpCycle => write!(f, "max number of jumps exceeded"),
        }
    }
}

impl Error for Errors {}
