use std::sync::mpsc::{Receiver, Sender, channel, SendError, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use crate::errors::Error;

static DEFAULT_ROUND_TIMELIMIT: u64 = 65;

type ThreadSafeReceiver<T> = Arc<Mutex<Receiver<T>>>;

fn to_thread_safe<T>(r: Receiver<T>) -> ThreadSafeReceiver<T> {
    Arc::new(Mutex::new(r))
}

pub struct RoundTimeOutObserver {
    timelimit: Duration,
    sender: Sender<()>,
    pub receiver: Receiver<()>,
    command_sender: SyncSender<Command>,
    command_receiver: ThreadSafeReceiver<Command>,
    thread: Option<JoinHandle<()>>,
}

pub enum Command {
    Stop,
}

impl RoundTimeOutObserver {
    pub fn new(timelimit_secs: u64) -> RoundTimeOutObserver {
        let (sender, receiver): (Sender<()>, Receiver<()>) = channel();
        let (command_sender, command_receiver): (SyncSender<Command>, Receiver<Command>) = sync_channel(0);
        RoundTimeOutObserver {
            timelimit: Duration::from_secs(timelimit_secs),
            thread: None,
            sender,
            receiver,
            command_sender,
            command_receiver: to_thread_safe(command_receiver),
        }
    }

    pub fn is_started(&self) -> bool {
        self.thread.is_some()
    }

    pub fn start(&mut self) -> Result<(), Error>{
        if self.is_started() {
            return Err(Error::TimerAlreadyStarted);
        }
        let sender = self.sender.clone();
        let command_receiver = self.command_receiver.clone();
        let timeout = self.timelimit;
        let handler = std::thread::Builder::new().name("RoundTimeoutObserverThread".to_string())
            .spawn(move || {
                let receiver = command_receiver.lock().unwrap();
                match receiver.recv_timeout(timeout) {
                    Ok(Command::Stop) => {}
                    Err(_e) => {
                        // time out, send timeout signal.
                        match sender.send(()) {
                            Ok(_) => {}
                            Err(e) => log::warn!("Round timeouted, but receiver not handle signal!: {:?}", e)
                        };
                    }
                }
            }).unwrap();
        self.thread = Some(handler);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), SendError<Command>> {
        self.thread = None;
        self.command_sender.send(Command::Stop)
    }
}

impl Drop for RoundTimeOutObserver {
    fn drop(&mut self) {
        // wait thread finished.
        if let Some(handler) = self.thread.take() {
            handler.join().unwrap();
        }
    }
}

#[test]
pub fn test_timeout_signal() {
    let mut observer = RoundTimeOutObserver::new(0);
    observer.start().unwrap();
    match observer.receiver.recv_timeout(Duration::from_millis(300)) {
        Ok(_) => assert_eq!(observer.is_started(), true),
        Err(e) => panic!("Timeout signal not received. {:?}", e),
    }
}

#[test]
pub fn test_timer_stop() {
    let mut observer = RoundTimeOutObserver::new(1);
    observer.start().unwrap();
    observer.stop().unwrap();
    match observer.receiver.recv_timeout(Duration::from_millis(1100)) {
        Ok(_) => panic!("Should not send stop signal."),
        Err(_e) => assert_eq!(observer.is_started(), false), // Observer thread should did stop.
    }
}

#[test]
#[should_panic(expected = "TimerAlreadyStarted")]
pub fn test_prevent_duplicate_start() {
    let mut observer = RoundTimeOutObserver::new(1);
    observer.start().unwrap();
    observer.start().unwrap();
}