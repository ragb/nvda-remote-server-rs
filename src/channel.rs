use tokio::io::{AsyncRead, AsyncWrite};

use crate::user::User;

#[derive(Debug)]
pub struct Channel<IO: AsyncRead + AsyncWrite> {
    pub id: String,
    pub users: Vec<User<IO>>,
}

impl<IO: AsyncRead + AsyncWrite> Channel<IO> {
    pub fn new(id: String) -> Channel<IO> {
        Channel {
            id,
            users: Vec::new(),
        }
    }
}
