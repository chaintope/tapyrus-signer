use std::sync::mpsc::{Receiver, Sender, channel, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;
use std::sync::{Arc, Mutex, RwLock};
use log::warn;
use crate::errors::Error;

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
    state: Arc<RwLock<State>>,
}

pub enum Command {
    Stop,
}

#[derive(Debug)]
pub struct State {
    started: bool,
}

impl RoundTimeOutObserver {
    pub fn new(timelimit_secs: u64) -> RoundTimeOutObserver {
        let (sender, receiver): (Sender<()>, Receiver<()>) = channel();
        let (command_sender, command_receiver): (SyncSender<Command>, Receiver<Command>) = sync_channel(1);
        RoundTimeOutObserver {
            timelimit: Duration::from_secs(timelimit_secs),
            thread: None,
            sender,
            receiver,
            command_sender,
            command_receiver: to_thread_safe(command_receiver),
            state: Arc::new(RwLock::new(State { started: false })),
        }
    }

    pub fn is_started(&self) -> bool {
        let guard = self.state.try_read()
            .expect("Can't read started state. is Locked.");
        guard.started
//        self.thread.try_lock().unwrap().is_some()
    }

    fn set_started_state(&self, flag: bool) {
        let mut state_writer = self.state.try_write().expect("Can't state change to started!");
        state_writer.started = flag;
    }

    pub fn start(&mut self) -> Result<(), Error> {
        if self.is_started() {
            return Err(Error::TimerAlreadyStarted);
        }
        let sender = self.sender.clone();
        let command_receiver = self.command_receiver.clone();
        let timelimit = self.timelimit;
        self.set_started_state(true);
        let thread_in_started = self.state.clone();
        let stop = move || {
            let mut state = thread_in_started.try_write()
                .expect("State can not change to stop.");
            state.started = false;
        };
        let handler = std::thread::Builder::new().name("RoundTimeoutObserverThread".to_string())
            .spawn(move || {
                // TODO: lock取れない場合はリトライした方が良いか？　多分lock取れないのはエラーにしといていいとは思うが。。
                let receiver = command_receiver.try_lock()
                    .expect("Command_receiver can not have lock.");
                match receiver.recv_timeout(timelimit) {
                    Ok(Command::Stop) => {
                        println!("Command::Stop received.");
                        stop();
                    }
                    Err(_e) => {
                        println!("Timelimit reached!");
                        stop();
                        // time out, send timeout signal.
                        match sender.send(()) {
                            Ok(_) => {},
                            Err(e) => log::warn!("Round timeouted, but receiver not handle signal!: {:?}", e)
                        };
                    }
                }
                println!("RoundTimeoutObserverThread finished.");
            }).unwrap();
        self.thread = Some(handler);
        Ok(())
    }

    pub fn stop(&mut self) {
        if self.is_started() {
            match self.command_sender.try_send(Command::Stop) {
                Ok(_) => {
                    // Should be wait to thread stopped.
                    match self.thread.take() {
                        Some(handler) => handler.join().expect("Timer thread invalid state."),
                        None => {}
                    }
                }
                Err(e) => {
                    println!("happend send error: {:?}", e);
                    warn!("RoundTimeoutObserver thread maybe already dead. error:{:?}", e);
                }
            }
        };
        self.set_started_state(false);
    }

    pub fn restart(&mut self) -> Result<(), Error> {
        self.stop();
        self.start()?;
        Ok(())
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
        Ok(_) => assert_eq!(observer.is_started(), false),
        Err(e) => panic!("Timeout signal not received. {:?}", e),
    }
}

#[test]
pub fn test_timer_stop() {
    let mut observer = RoundTimeOutObserver::new(1);
    observer.start().unwrap();
    observer.stop();
    match observer.receiver.recv_timeout(Duration::from_millis(1100)) {
        Ok(_) => panic!("Should not send stop signal."),
        Err(_e) => assert_eq!(observer.is_started(), false), // Observer thread should did stop.
    }
}

#[test]
pub fn test_prevent_duplicate_start() {
    let mut observer = RoundTimeOutObserver::new(1);
    observer.start().unwrap();
    match observer.start() {
        Ok(_) => panic!("Should be Error!"),
        Err(e) => {
            let error = format!("{:?}", e);
            assert_eq!(error, "TimerAlreadyStarted");
        }
    }
}

#[test]
pub fn test_timeout_and_restart() {
    let mut observer = RoundTimeOutObserver::new(1);
    observer.start().unwrap();
    assert_eq!(observer.is_started(), true);
    match observer.receiver.recv_timeout(Duration::from_millis(1100)) {
        Ok(_) => assert_eq!(observer.is_started(), false),
        Err(e) => panic!("Timeout signal not received. {:?}", e),
    }
    println!("2nd round start.");
    observer.restart().unwrap();
    match observer.receiver.recv_timeout(Duration::from_millis(1500)) {
        Ok(_) => assert_eq!(observer.is_started(), false),
        Err(e) => panic!("Timeout signal not received. {:?}", e),
    }
}