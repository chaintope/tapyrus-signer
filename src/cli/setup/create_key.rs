use crate::cli::setup::traits::Response;
use crate::errors::Error;
use crate::key::generate_key_pair;
use clap::{App, ArgMatches, SubCommand};
use std::fmt;
use tapyrus::{PrivateKey, PublicKey};

pub struct CreateKeyResponse {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl CreateKeyResponse {
    fn new(private_key: PrivateKey, public_key: PublicKey) -> Self {
        CreateKeyResponse {
            private_key: private_key,
            public_key: public_key,
        }
    }
}

impl Response for CreateKeyResponse {}

impl fmt::Display for CreateKeyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            self.private_key.to_wif(),
            hex::encode(&self.public_key.key.serialize()[..]),
        )
    }
}

pub struct CreateKeyCommand {}

impl<'a> CreateKeyCommand {
    pub fn execute(_matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {
        let (private_key, public_key) = generate_key_pair();
        Ok(Box::new(CreateKeyResponse::new(private_key, public_key)))
    }
    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("createkey")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use tapyrus::{PrivateKey, PublicKey};

    #[test]
    fn test_format() {
        let private_key =
            PrivateKey::from_wif("KzZtqg6QKr4TaifSWNsSXfH1h7eHDKJL7rGV3w9Tx2tL83GhPdLv").unwrap();
        let public_key = PublicKey::from_str(
            "0369d39154c0d011db02085392142e369d920c2531fe38e14484546ee6713465d6",
        )
        .unwrap();
        let response = CreateKeyResponse::new(private_key, public_key);
        assert_eq!(format!("{}", response), "KzZtqg6QKr4TaifSWNsSXfH1h7eHDKJL7rGV3w9Tx2tL83GhPdLv 0369d39154c0d011db02085392142e369d920c2531fe38e14484546ee6713465d6")
    }
}
