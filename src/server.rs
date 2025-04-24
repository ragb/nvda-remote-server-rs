use std::{collections::HashMap, sync::atomic::AtomicUsize};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{channel::Channel, user::User};

#[derive(Debug)]
pub struct Server<IO: AsyncRead + AsyncWrite> {
    pub channels: HashMap<String, Channel<IO>>,
    user_id_gen: AtomicUsize,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Server<IO> {
    pub fn new() -> Server<IO> {
        Server {
            channels: HashMap::new(),
            user_id_gen: AtomicUsize::new(0),
        }
    }

    fn new_user_id(&self) -> usize {
        self.user_id_gen
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn new_user(self, io: IO) -> User<IO> {
        User::new(self.new_user_id(), io)
    }

    fn find_or_create_channel(&mut self, id: &str) -> &mut Channel<IO> {
        self.channels
            .entry(id.to_string())
            .or_insert_with(|| Channel::new(id.to_string()))
    }
}
