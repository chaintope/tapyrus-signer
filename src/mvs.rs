// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

extern crate redis;

use redis::{Client, Commands, ControlFlow, PubSubCommands};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

trait AppState {
    fn client(&self) -> &Arc<Client>;
}

struct Ctx {
    pub client: Arc<Client>,
}

impl Ctx {
    fn new() -> Ctx {
        let client = Client::open("redis://localhost/").unwrap();
        Ctx {
            client: Arc::new(client),
        }
    }
}

impl AppState for Ctx {
    fn client(&self) -> &Arc<Client> {
        &self.client
    }
}

fn subscribe(state: &impl AppState) -> thread::JoinHandle<()> {
    let client = Arc::clone(state.client());
    thread::spawn(move || {
        let mut conn = client.get_connection().unwrap();

        conn.subscribe(&["boo"], |msg| {
            let ch = msg.get_channel_name();
            let payload: String = msg.get_payload().unwrap();
            match payload.as_ref() {
                "candidate_block" => candidate_block( &payload),
                "signature" => signature( &payload),
                "completed_block" => completed_block( &payload),
                "roundfailure" => roundfailure( &payload),
                "end" => ControlFlow::Break(()),
                a => {
                    println!("unknown message: {}", a);
                    ControlFlow::Break(())
                }
            }
        }).unwrap();
    })
}

fn candidate_block(message: &str) -> ControlFlow<()> {
    println!("call candidateBlock: {}", message);
    publish("signature");
    ControlFlow::Continue
}

fn signature(message: &str) -> ControlFlow<()> {
    println!("call signature: {}", message);
    publish("completed_block");
    ControlFlow::Continue
}

fn completed_block(message: &str) -> ControlFlow<()> {
    println!("call completedBlock: {}", message);
    publish("end");
    ControlFlow::Continue
}

fn roundfailure(message: &str) -> ControlFlow<()> {
    println!("call roundfailure: {}", message);
    publish("end");
    ControlFlow::Continue
}

fn publish(message: &str) -> thread::JoinHandle<()> {
    let ctx = Ctx::new();
    let client = Arc::clone(ctx.client());
    let message_in_thread = message.to_string();
    thread::spawn(move || {
        let conn = client.get_connection().unwrap();
        thread::sleep(Duration::from_millis(500));
        println!("Publish {} to boo.", message_in_thread);
        let _: () = conn.publish("boo", message_in_thread).unwrap();
    })
}

fn main() {
    let ctx = Ctx::new();
    let handle = subscribe(&ctx);
    publish( "candidate_block");
    handle.join().unwrap();
}
