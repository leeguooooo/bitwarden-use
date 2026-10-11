use futures_util::{SinkExt as _, StreamExt as _};

#[derive(Clone, Copy, Debug)]
pub enum Message {
    Sync,
    Logout,
}

type WsStream = tokio_tungstenite::WebSocketStream<reqwest::Upgraded>;
type WsSink = futures_util::stream::SplitSink<
    WsStream,
    tokio_tungstenite::tungstenite::Message,
>;
type SendingChannels = std::sync::Arc<
    tokio::sync::RwLock<Vec<tokio::sync::mpsc::UnboundedSender<Message>>>,
>;

pub struct Handler {
    write: Option<WsSink>,
    read_handle: Option<tokio::task::JoinHandle<()>>,
    sending_channels: SendingChannels,
    connecting: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Handler {
    pub fn new() -> Self {
        Self {
            write: None,
            read_handle: None,
            sending_channels: std::sync::Arc::new(tokio::sync::RwLock::new(
                Vec::new(),
            )),
            connecting: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        }
    }

    /// Claim the right to open a connection. Returns None when one is
    /// already open or another task is opening it; the claim is released
    /// when the returned guard drops.
    pub fn begin_connect(&self) -> Option<ConnectGuard> {
        if self.is_connected()
            || self
                .connecting
                .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return None;
        }
        Some(ConnectGuard {
            connecting: self.connecting.clone(),
            sending_channels: self.sending_channels.clone(),
        })
    }

    /// Install a connection opened with `connect`. The receivers handed out
    /// by `get_channel` stay subscribed.
    pub fn install(
        &mut self,
        (write, read_handle): (WsSink, tokio::task::JoinHandle<()>),
    ) {
        if let Some(old) = self.read_handle.take() {
            old.abort();
        }
        self.write = Some(write);
        self.read_handle = Some(read_handle);
    }

    pub fn is_connected(&self) -> bool {
        self.write.is_some()
            && self
                .read_handle
                .as_ref()
                .is_some_and(|handle| !handle.is_finished())
    }

    pub async fn get_channel(
        &self,
    ) -> tokio::sync::mpsc::UnboundedReceiver<Message> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.sending_channels.write().await.push(tx);
        rx
    }
}

pub struct ConnectGuard {
    connecting: std::sync::Arc<std::sync::atomic::AtomicBool>,
    sending_channels: SendingChannels,
}

impl ConnectGuard {
    /// Open the websocket and start reading from it. Runs without the agent
    /// state lock held, so a slow or silent server does not block other
    /// commands.
    pub async fn connect(
        &self,
        access_token: &str,
    ) -> anyhow::Result<(WsSink, tokio::task::JoinHandle<()>)> {
        let upgraded =
            rbw::actions::notifications_websocket(access_token).await?;
        let ws_stream = WsStream::from_raw_socket(
            upgraded,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await;
        let (mut write, read) = ws_stream.split();

        write
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "{\"protocol\":\"messagepack\",\"version\":1}\x1e".into(),
            ))
            .await?;

        let sending_channels = self.sending_channels.clone();
        let read_future = async move {
            let sending_channels = &sending_channels;
            read.for_each(|message| async move {
                match message {
                    Ok(message) => {
                        if let Some(message) = parse_message(message) {
                            let sending_channels =
                                sending_channels.read().await;
                            let sending_channels =
                                sending_channels.as_slice();
                            for channel in sending_channels {
                                channel.send(message).unwrap();
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("websocket error: {e:?}");
                    }
                }
            })
            .await;
        };

        Ok((write, tokio::spawn(read_future)))
    }
}

impl Drop for ConnectGuard {
    fn drop(&mut self) {
        self.connecting
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

fn parse_message(
    message: tokio_tungstenite::tungstenite::Message,
) -> Option<Message> {
    let tokio_tungstenite::tungstenite::Message::Binary(data) = message
    else {
        return None;
    };

    // the first few bytes with the 0x80 bit set, plus one byte terminating the length contain the length of the message
    let len_buffer_length = data.iter().position(|&x| (x & 0x80) == 0)? + 1;

    let unpacked_messagepack =
        rmpv::decode::read_value(&mut &data[len_buffer_length..]).ok()?;

    let unpacked_message = unpacked_messagepack.as_array()?;
    let message_type = unpacked_message.first()?.as_u64()?;
    // invocation
    if message_type != 1 {
        return None;
    }
    let target = unpacked_message.get(3)?.as_str()?;
    if target != "ReceiveMessage" {
        return None;
    }

    let args = unpacked_message.get(4)?.as_array()?;
    let map = args.first()?.as_map()?;
    for (k, v) in map {
        if k.as_str()? == "Type" {
            let ty = v.as_i64()?;
            return match ty {
                11 => Some(Message::Logout),
                _ => Some(Message::Sync),
            };
        }
    }

    None
}
