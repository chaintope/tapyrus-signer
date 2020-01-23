use crate::net::{ConnectionManager, ConnectionManagerError, Message, SignerID};
use redis::ControlFlow;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

pub type SpyMethod = Box<dyn Fn(Arc<Message>) -> () + Send + 'static>;

/// ConnectionManager for testing.
pub struct TestConnectionManager {
    /// This is count of messages. TestConnectionManager waits for receiving the number of message.
    pub receive_count: u32,
    /// sender of message
    pub sender: Sender<Message>,
    /// receiver of message
    pub receiver: Receiver<Message>,
    /// A function which is called when the node try to broadcast messages.
    pub broadcast_assert: SpyMethod,
}

impl TestConnectionManager {
    pub fn new(receive_count: u32, broadcast_assert: SpyMethod) -> Self {
        let (sender, receiver): (Sender<Message>, Receiver<Message>) = channel();
        TestConnectionManager {
            receive_count,
            sender,
            receiver,
            broadcast_assert,
        }
    }
}

impl ConnectionManager for TestConnectionManager {
    type ERROR = crate::errors::Error;
    fn broadcast_message(&self, message: Message) {
        let rc_message = Arc::new(message);
        (self.broadcast_assert)(rc_message.clone());
    }

    fn send_message(&self, message: Message) {
        let rc_message = Arc::new(message);
        (self.broadcast_assert)(rc_message.clone());
    }

    fn start(
        &self,
        mut message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + 'static,
        _id: SignerID,
    ) -> JoinHandle<()> {
        for _count in 0..self.receive_count {
            match self.receiver.recv() {
                Ok(message) => {
                    log::debug!("Test message receiving!! {:?}", message.message_type);
                    message_processor(message);
                }
                Err(e) => log::warn!("happend receiver error: {:?}", e),
            }
        }
        thread::Builder::new()
            .name("TestConnectionManager start Thread".to_string())
            .spawn(|| {
                thread::sleep(Duration::from_millis(300));
            })
            .unwrap()
    }

    fn error_handler(&mut self) -> Option<Receiver<ConnectionManagerError<crate::errors::Error>>> {
        None::<Receiver<ConnectionManagerError<crate::errors::Error>>>
    }
}
