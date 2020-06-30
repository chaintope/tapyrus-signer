use crate::net::{ConnectionManager, ConnectionManagerError, Message, SignerID};
use redis::ControlFlow;
use std::cell::RefCell;
use std::sync::mpsc::channel;
use std::thread;
use std::thread::JoinHandle;

use crate::errors;

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
        let TestConnectionManager {
            should_broadcast,
            broadcasted,
            should_send,
            sent,
        } = self;
        assert_eq!(broadcasted.into_inner(), should_broadcast);
        assert_eq!(sent.into_inner(), should_send);
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
        _message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + 'static,
        _id: SignerID,
    ) -> JoinHandle<()> {
        // do nothing.

        // This is for just returns JoinHandle instance.
        thread::Builder::new().spawn(|| {}).unwrap()
    }

    fn test_connection(&self) -> Result<(), errors::Error> {
        Ok(())
    }

    fn take_error(
        &mut self,
    ) -> Result<ConnectionManagerError<Self::ERROR>, std::sync::mpsc::TryRecvError> {
        let (_s, r) = channel();
        r.try_recv()
    }
}
