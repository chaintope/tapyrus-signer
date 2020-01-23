use crate::net::{ConnectionManager, ConnectionManagerError, Message, SignerID};
use redis::ControlFlow;
use std::cell::RefCell;
use std::sync::mpsc::Receiver;
use std::thread;
use std::thread::JoinHandle;

pub struct TestConnectionManager {
    should_broadcast: Vec<Message>,
    pub broadcasted: RefCell<Vec<Message>>,

    should_send: Vec<Message>,
    pub sent: RefCell<Vec<Message>>,
}

impl TestConnectionManager {
    pub fn new() -> Self {
        Self {
            should_broadcast: vec![],
            broadcasted: RefCell::new(vec![]),

            should_send: vec![],
            sent: RefCell::new(vec![]),
        }
    }

    pub fn assert(self) {
        if let TestConnectionManager {
            should_broadcast,
            broadcasted,
            should_send,
            sent,
        } = self
        {
            assert_eq!(should_broadcast, broadcasted.into_inner());
            assert_eq!(should_send, sent.into_inner());
        }
    }

    pub fn should_broadcast(&mut self, message: Message) {
        self.should_broadcast.push(message);
    }

    pub fn should_send(&mut self, message: Message) {
        self.should_send.push(message);
    }
}

impl ConnectionManager for TestConnectionManager {
    type ERROR = crate::errors::Error;

    fn broadcast_message(&self, message: Message) {
        let mut list = self.broadcasted.borrow_mut();
        list.push(message);
    }

    fn send_message(&self, message: Message) {
        let mut list = self.sent.borrow_mut();
        list.push(message);
    }

    fn start(
        &self,
        mut message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + 'static,
        _id: SignerID,
    ) -> JoinHandle<()> {
        // do nothing.

        // This is for just returns JoinHandle instance.
        thread::Builder::new().spawn(|| {}).unwrap()
    }

    fn error_handler(&mut self) -> Option<Receiver<ConnectionManagerError<Self::ERROR>>> {
        None::<Receiver<ConnectionManagerError<crate::errors::Error>>>
    }
}
