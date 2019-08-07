use std::str::FromStr;

use bitcoin::PublicKey;
use clap::{App, Arg};
use log;
use serde::Deserialize;

pub const OPTION_NAME_CONFIG: &str = "config";
pub const OPTION_NAME_PUBLIC_KEY: &str = "publickeys";
pub const OPTION_NAME_PRIVATE_KEY: &str = "privatekey";
pub const OPTION_NAME_THRESHOLD: &str = "threshold";
pub const OPTION_NAME_MASTER_FLAG: &str = "master_flag";
pub const OPTION_NAME_RPC_ENDPOINT_HOST: &str = "rpc_endpoint_host";
pub const OPTION_NAME_RPC_ENDPOINT_PORT: &str = "rpc_endpoint_port";
pub const OPTION_NAME_RPC_ENDPOINT_USER: &str = "rpc_endpoint_user";
pub const OPTION_NAME_RPC_ENDPOINT_PASS: &str = "rpc_endpoint_pass";

pub const OPTION_NAME_REDIS_HOST: &str = "redis_host";
pub const OPTION_NAME_REDIS_PORT: &str = "redis_port";

/// round category params.
pub const OPTION_NAME_ROUND_DURATION: &str = "round_duration";

/// log category params.
pub const OPTION_NAME_LOG_QUIET: &str = "log_quiet";
pub const OPTION_NAME_LOG_LEVEL: &str = "log_level";

/// default config file name
pub const DEFAULT_CONFIG_FILENAME: &str = "signer_config.toml";

#[derive(Debug, Deserialize)]
pub struct Config {
    pub signer: Option<Signer>,
}

#[derive(Debug, Deserialize)]
pub struct Signer {
    publickeys: Vec<String>,
    privatekey: String,
    threshold: u8,
}

pub struct CommandArgs<'a> {
    pub matches: clap::ArgMatches<'a>,
    pub config: Option<Config>
}

impl<'a> CommandArgs<'a> {
    pub fn load(matches: clap::ArgMatches) -> Result<CommandArgs, crate::errors::Error> {
        // load from config file if exists.
        let config_file = matches.value_of(OPTION_NAME_CONFIG).unwrap();
        match read_config(config_file) {
            Ok(c) => Ok(CommandArgs{matches, config: Some(c)}),
            Err(crate::errors::Error::ConfigFileIOError(ioerror)) => {
                log::warn!("config file read error: {:?}", ioerror);
                Ok(CommandArgs{matches, config: None})
            }
            Err(e) => Err(e),
        }
    }

    pub fn public_keys(&self) -> Vec<PublicKey> {
        let pubkeys = self.matches.values_of(OPTION_NAME_PUBLIC_KEY)
            .map(|vs| vs.map(|v| v).collect());
        let signer: Option<&Signer> = self.config.as_ref().map(|c| c.signer.as_ref()).and_then(|o| o);
        let pubkeys_within_config: Option<Vec<&str>> = signer.map(|s| s.publickeys.iter().map(|s| s as &str).collect());
        // TODO: maybe panic is not suitable? should be return result<vec, error> ?
        let specified = pubkeys.or(pubkeys_within_config).expect("Must be specified public_keys.");
        let parse_results: Vec<Result<PublicKey, String>> = specified.iter().map(|s| {
            PublicKey::from_str(s).or_else(|_e| Err(format!("'{}' is invalid public key format.\n", s)))
        }).collect();
        let mut iter = parse_results.iter();
        let errors: Vec<&String> = iter.by_ref().filter(|r| r.is_err())
            .map(|r| r.as_ref().err().unwrap()).collect();
        if !errors.is_empty() {
            panic!("{:?}", errors.into_iter().fold(String::new(), |s, e| s + e));
        }
        parse_results.into_iter().map(|r| r.unwrap()).collect()
    }

    pub fn threshold(&self) -> u8 {
        let num: Option<u8> = self.matches.value_of(OPTION_NAME_THRESHOLD).and_then(|v| v.parse().ok());
        let num_within_config = self.config.as_ref().map(|c| c.signer.as_ref()).and_then(|o| o)
            .map(|s| s.threshold);
        // TODO: should be retrn Result<u8, Error>?
        num.or(num_within_config).expect("Must be specified threshold.")
    }
}

fn read_config(file_path: &str) -> Result<Config, crate::errors::Error> {
    let contents = std::fs::read_to_string(file_path)?;
    let toml: Config = toml::from_str(&contents)?;
    Ok(toml)
}

/// command example:
/// ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e --privatekey=cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA -t 2 --master
pub fn get_options(duration_default: &str) -> clap::App {
    App::new("node")
        .about("Tapyrus siner node")
        .arg(Arg::with_name(OPTION_NAME_CONFIG)
            .short("c")
            .long("config")
            .value_name("CONFIG_FILE_PATH")
            .default_value(DEFAULT_CONFIG_FILENAME)
            .help("Load settings from this file. when defined both in file and command line args, then command line args take precedence."))
        .arg(Arg::with_name(OPTION_NAME_PUBLIC_KEY)
            .short("p")
            .long("publickey")
            .value_name("PUBKEY")
            .multiple(true)
            .help("Tapyrus signer public key. not need '0x' prefix. example: 03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc"))
        .arg(Arg::with_name(OPTION_NAME_THRESHOLD)
            .short("t")
            .long("threshold")
            .value_name("NUM")
            .help("The threshold of enough signer. it must be less than specified public keys."))
        .arg(Arg::with_name(OPTION_NAME_PRIVATE_KEY)
            .long("privatekey")
            .value_name("PRIVATE_KEY")
            .help("The PrivateKey of this signer node. WIF format."))
        .arg(Arg::with_name(OPTION_NAME_MASTER_FLAG)
            .long("master")
            .help("Master Node Flag. If launch as Master node, then set this option."))
        .arg(Arg::with_name(OPTION_NAME_RPC_ENDPOINT_HOST)
            .long("rpchost")
            .value_name("HOST_NAME or IP")
            .help("TapyrusCore RPC endpoint host.")
            .default_value("127.0.0.1"))
        .arg(Arg::with_name(OPTION_NAME_RPC_ENDPOINT_PORT)
            .long("rpcport")
            .value_name("PORT")
            .help("TapyrusCore RPC endpoint port number. These are TapyrusCore default port, mainnet: 2377, testnet: 12377, regtest: 12381.")
            .default_value("2377"))
        .arg(Arg::with_name(OPTION_NAME_RPC_ENDPOINT_USER)
            .long("rpcuser")
            .value_name("USER")
            .help("TapyrusCore RPC user name."))
        .arg(Arg::with_name(OPTION_NAME_RPC_ENDPOINT_PASS)
            .long("rpcpass")
            .value_name("PASS")
            .help("TapyrusCore RPC user password."))
        .arg(Arg::with_name(OPTION_NAME_REDIS_HOST)
            .long("redishost")
            .value_name("HOST_NAME or IP")
            .default_value("127.0.0.1")
            .help("Redis host."))
        .arg(Arg::with_name(OPTION_NAME_REDIS_PORT)
            .long("redisport")
            .value_name("PORT")
            .default_value("6379")
            .help("Redis port."))
        .arg(Arg::with_name(OPTION_NAME_LOG_QUIET)
            .long("quiet")
            .short("q")
            .takes_value(false)
            .help("Silent mode. Do not output logs."))
        .arg(Arg::with_name(OPTION_NAME_LOG_LEVEL)
            .long("log")
            .short("l")
            .takes_value(true)
            .possible_values(&["error", "warn", "info", "debug", "trace"])
            .default_value("info")
            .help("Set the log leve."))
        .arg(Arg::with_name(OPTION_NAME_ROUND_DURATION)
            .long("duration")
            .short("d")
            .takes_value(true)
            .value_name("SECs")
            .default_value(duration_default)
            .help("Round interval times(sec)."))
}

#[test]
fn test_load() {
    let matches = get_options("60")
        .get_matches_from(vec!["node", "-c=tests/resources/signer_config.toml"]);
    let args = CommandArgs::load(matches);
    assert!(args.is_ok());
    assert!(args.unwrap().config.is_some());
}

#[test]
fn test_allow_no_exists_config_file() {
    let matches = get_options("60")
        .get_matches_from(vec!["node", "-c=hoge.toml"]);
    let args = CommandArgs::load(matches);
    assert!(args.is_ok());
    assert!(args.unwrap().config.is_none());
}

#[test]
#[should_panic(expected = "InvalidTomlFormat")]
fn test_invalid_format_config_file() {
    let matches = get_options("60")
        .get_matches_from(vec!["node", "-c=tests/resources/invalid_format.toml"]);
    let _args = CommandArgs::load(matches).unwrap();
}

#[test]
fn test_load_from_file() {
    let matches = get_options("60")
        .get_matches_from(vec!["node", "-c=tests/resources/signer_config.toml"]);
    let args = CommandArgs::load(matches).unwrap();
    let pubkeys = args.public_keys();
    assert_eq!(pubkeys.len(), 3);
    assert_eq!(pubkeys[0].to_string(), "033cfe7fa1be58191b9108883543e921d31dc7726e051ee773e0ea54786ce438f8");
    assert_eq!(pubkeys[1].to_string(), "020464074b94702e9b07803d247021943bdcc1f8700b92b66defb7fadd76e80acf");
    assert_eq!(pubkeys[2].to_string(), "02cbe0ad70ffe110d097db648fda20bef14dc72b5c9979c137c451820c176ac23f");

    let threshold = args.threshold();
    assert_eq!(threshold, 2);
}

#[test]
fn test_priority_commandline() {
    let matches = get_options("60")
        .get_matches_from(vec!["node", "-c=tests/resources/signer_config.toml",
                               "-p=020464074b94702e9b07803d247021943bdcc1f8700b92b66defb7fadd76e80acf",
                               "-p=033cfe7fa1be58191b9108883543e921d31dc7726e051ee773e0ea54786ce438f8",
                               "--threshold=1"]);
    let args = CommandArgs::load(matches).unwrap();
    let pubkeys = args.public_keys();
    assert_eq!(pubkeys.len(), 2);
    assert_eq!(pubkeys[0].to_string(), "020464074b94702e9b07803d247021943bdcc1f8700b92b66defb7fadd76e80acf");
    assert_eq!(pubkeys[1].to_string(), "033cfe7fa1be58191b9108883543e921d31dc7726e051ee773e0ea54786ce438f8");
    let threshold = args.threshold();
    assert_eq!(threshold, 1);
}

#[test]
#[should_panic(expected = "\\'aaaa\\' is invalid public key format.\\n\\'bbbb\\' is invalid public key format.\\n")]
fn test_invid_pubkeys() {
    let matches = get_options("60")
        .get_matches_from(vec!["node", "-c=tests/resources/signer_config.toml",
                               "-p=aaaa",
                               "-p=bbbb"]);
    let args = CommandArgs::load(matches).unwrap();
    let _pubkeys = args.public_keys();
}

#[test]
#[should_panic(expected = "Must be specified public_keys.")]
fn test_no_pubkeys() {
    let matches = get_options("60")
        .get_matches_from(vec!["node", "-c=tests/resources/no_signer_signer_config.toml"]);
    let args = CommandArgs::load(matches).unwrap();
    let _pubkeys = args.public_keys();
}
