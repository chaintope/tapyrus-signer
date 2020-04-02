extern crate tapyrus_signer;

use clap::App;
use tapyrus_signer::cli::setup::create_key::CreateKeyCommand;
use tapyrus_signer::cli::setup::create_node_vss::CreateNodeVssCommand;
use tapyrus_signer::cli::setup::traits::Response;
use tapyrus_signer::errors::Error;

fn main() {
    let matches = App::new("Setup")
        .subcommand(CreateKeyCommand::args())
        .subcommand(CreateNodeVssCommand::args())
        .get_matches();
    let result: Result<Box<dyn Response>, Error> = match matches.subcommand_name() {
        Some("createkey") => CreateKeyCommand::execute(
            matches
                .subcommand_matches("createkey")
                .expect("invalid args"),
        ),
        Some("createnodevss") => CreateNodeVssCommand::execute(
            matches
                .subcommand_matches("createnodevss")
                .expect("invalid args"),
        ),
        None => return println!("No subcommand was used"),
        _ => unreachable!(),
    };
    match result {
        Ok(response) => println!("{}", response),
        Err(e) => println!("{}", e),
    }
}
