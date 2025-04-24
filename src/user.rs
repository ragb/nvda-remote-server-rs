use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::{bytes::Bytes, codec::{AnyDelimiterCodec, Framed, FramedRead, FramedWrite}};


#[derive(Debug, thiserror::Error)]
enum UserError {
    #[error("User disconnected")]
    Disconnected,

    #[error("Invalid JSON")]
    InvalidJson,

    #[error("Invalid command")]
    InvalidCommand,

    #[error("Not authenticated")]
NotAuthenticated,
}

type Result<T> = std::result::Result<T, UserError>;

#[derive(Debug)]
pub struct User<IO: AsyncRead + AsyncWrite> {
    pub id: usize,
    framed: Framed<IO, AnyDelimiterCodec>,
}

 \      \impl<IO: AsyncRead + AsyncWrite + Unpin> User<IO> {
    pub fn new(id: usize, io: IO) -> User<IO> {
        let lines_codec_bytes =
        AnyDelimiterCodec::new_with_max_length(b"\n".to_vec(), b"\n".to_vec(), 1024 * 1024);

        let framed = Framed::new(io, lines_codec_bytes);
        User { id, framed }
    }

    async fn parse_command(&mut self) -> anyhow::Result<String> {
        let bytes = self.framed.next().await.ok_or_else(|| anyhow::anyhow!("EOF"))??;
        let command = String::from_utf8(bytes.to_vec())?;
        Ok(command)
    }

    pub async fn send_bytes(&mut self, bytes: Bytes) -> anyhow::Result<()> {
        self.framed.send(bytes).await?;
        self.framed.flush().await?;
        Ok(())
    }
}
