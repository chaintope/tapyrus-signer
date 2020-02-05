// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use std::str::FromStr;

use crate::signer_node::ROUND_INTERVAL_DEFAULT_SECS;
use bitcoin::{Address, PrivateKey, PublicKey};
use clap::{App, Arg};
use log;
use serde::Deserialize;
use std::path::PathBuf;

pub const OPTION_NAME_CONFIG: &str = "config";

/// # Signer Config
pub const OPTION_NAME_TO_ADDRESS: &str = "coinbase_pay_to_address";
pub const OPTION_NAME_PUBLIC_KEY: &str = "publickeys";
pub const OPTION_NAME_PRIVATE_KEY: &str = "privatekey";
pub const OPTION_NAME_THRESHOLD: &str = "threshold";

/// # RPC Config
pub const OPTION_NAME_RPC_ENDPOINT_HOST: &str = "rpc_endpoint_host";
pub const OPTION_NAME_RPC_ENDPOINT_PORT: &str = "rpc_endpoint_port";
pub const OPTION_NAME_RPC_ENDPOINT_USER: &str = "rpc_endpoint_user";
pub const OPTION_NAME_RPC_ENDPOINT_PASS: &str = "rpc_endpoint_pass";

/// # Redis Config
pub const OPTION_NAME_REDIS_HOST: &str = "redis_host";
pub const OPTION_NAME_REDIS_PORT: &str = "redis_port";

/// # General Config
/// round category params.
pub const OPTION_NAME_ROUND_DURATION: &str = "round_duration";
/// log category params.
pub const OPTION_NAME_LOG_QUIET: &str = "log_quiet";
pub const OPTION_NAME_LOG_LEVEL: &str = "log_level";
/// daemonize
pub const OPTION_NAME_DAEMON: &str = "daemon";
pub const OPTION_NAME_PID: &str = "pid";
pub const OPTION_NAME_LOG_FILE: &str = "log_file";
/// Others
pub const OPTION_NAME_SKIP_WAITING_IBD: &str = "skip_waiting_ibd";

/// # Default Values
pub const DEFAULT_RPC_HOST: &str = "127.0.0.1";
pub const DEFAULT_RPC_PORT: &str = "2377";
pub const DEFAULT_RPC_USERNAME: &str = "";
pub const DEFAULT_RPC_PASSWORD: &str = "";
pub const DEFAULT_REDIS_HOST: &str = "127.0.0.1";
pub const DEFAULT_REDIS_PORT: &str = "6379";
pub const DEFAULT_LOG_LEVEL: &str = "info";

lazy_static! {
    pub static ref DEFAULT_PID: PathBuf = {
        let mut v = std::env::temp_dir();
        v.push("tapyrus-signer.pid");
        v
    };
    pub static ref DEFAULT_LOG_FILE: PathBuf = {
        let mut v = std::env::temp_dir();
        v.push("tapyrus-signer.log");
        v
    };
}

/// default config file name
pub const DEFAULT_CONFIG_FILENAME: &str = "signer_config.toml";

#[derive(Debug, Deserialize, Default)]
struct SignerToml {
    to_address: Option<String>,
    publickeys: Option<Vec<String>>,
    privatekey: Option<String>,
    threshold: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct RpcToml {
    rpc_endpoint_host: Option<String>,
    rpc_endpoint_port: Option<u32>,
    rpc_endpoint_user: Option<String>,
    rpc_endpoint_pass: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RedisToml {
    redis_host: Option<String>,
    redis_port: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct GeneralToml {
    round_duration: Option<u64>,
    log_level: Option<String>,
    log_quiet: Option<bool>,
    skip_waiting_ibd: Option<bool>,
    daemon: Option<bool>,
    pid: Option<String>,
    log_file: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ConfigToml {
    signer: Option<SignerToml>,
    rpc: Option<RpcToml>,
    redis: Option<RedisToml>,
    general: Option<GeneralToml>,
}

pub struct CommandArgs<'a> {
    matches: clap::ArgMatches<'a>,
    config: Option<ConfigToml>,
}

pub struct SignerCommandArgs<'a> {
    to_address: Option<&'a str>,
    private_key: Option<&'a str>,
    public_keys: Option<Vec<&'a str>>,
    threshold: Option<u8>,
}

pub struct SignerConfig<'a> {
    command_args: SignerCommandArgs<'a>,
    toml_config: Option<&'a SignerToml>,
}

impl<'a> SignerConfig<'a> {
    pub fn to_address(&self) -> Address {
        let value_within_config: Option<&str> = self
            .toml_config
            .and_then(|config| config.to_address.as_ref())
            .map(|p| p as &str);
        self.command_args
            .to_address
            .or(value_within_config)
            .and_then(|s| match Address::from_str(s) {
                Ok(p) => {
                    assert_eq!(
                        p.network,
                        self.private_key().network,
                        "Network should be same among with to_address and WIF of private_key"
                    );
                    Some(p)
                }
                Err(e) => panic!(format!("'{}' is invalid address. error msg: {:?}", s, e)),
            })
            .expect("Must be specified to_address.")
    }

    pub fn public_keys(&self) -> Vec<PublicKey> {
        let vec_string: Option<&Vec<String>> = self
            .toml_config
            .and_then(|config| config.publickeys.as_ref());
        let pubkeys_within_config: Option<Vec<&str>> =
            vec_string.map(|v| v.iter().map(|s| &s as &str).collect());
        // TODO: maybe panic is not suitable? should be return result<vec, error> ?
        let specified = self
            .command_args
            .public_keys
            .as_ref()
            .or(pubkeys_within_config.as_ref())
            .expect("Must be specified public_keys.");
        let parse_results: Vec<Result<PublicKey, String>> = specified
            .iter()
            .map(|s| {
                PublicKey::from_str(s)
                    .or_else(|_e| Err(format!("'{}' is invalid public key format.\n", s)))
            })
            .collect();

        // separate invalid pubkey while doing convert.
        let mut iter = parse_results.iter();
        let errors: Vec<&String> = iter
            .by_ref()
            .filter(|r| r.is_err())
            .map(|r| r.as_ref().err().unwrap())
            .collect();
        if !errors.is_empty() {
            panic!("{:?}", errors.into_iter().fold(String::new(), |s, e| s + e));
        }
        // all keys are valid
        parse_results.into_iter().map(|r| r.unwrap()).collect()
    }

    pub fn threshold(&self) -> u8 {
        // TODO: should be retrn Result<u8, Error>?
        self.command_args
            .threshold
            .or(self.toml_config.and_then(|config| config.threshold))
            .expect("Must be specified threshold.")
    }

    pub fn private_key(&self) -> PrivateKey {
        let private_key_within_config: Option<&str> = self
            .toml_config
            .and_then(|config| config.privatekey.as_ref())
            .map(|p| p as &str);
        self.command_args
            .private_key
            .or(private_key_within_config)
            .and_then(|s| match PrivateKey::from_str(s) {
                Ok(p) => Some(p),
                Err(e) => panic!(format!(
                    "'{}' is invalid WIF format!. error msg: {:?}",
                    s, e
                )),
            })
            .expect("Must be specified private_key.")
    }
}

pub struct RpcCommandArgs<'a> {
    pub host: Option<&'a str>,
    pub port: Option<&'a str>,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
}

pub struct RpcConfig<'a> {
    pub command_args: RpcCommandArgs<'a>,
    pub toml_config: Option<&'a RpcToml>,
}

impl<'a> RpcConfig<'a> {
    pub fn host(&'a self) -> &'a str {
        let toml_value = self
            .toml_config
            .and_then(|config| config.rpc_endpoint_host.as_ref())
            .map(|s| s as &str);
        self.command_args
            .host
            .or(toml_value)
            .unwrap_or(DEFAULT_RPC_HOST)
    }
    pub fn port(&'a self) -> u32 {
        let toml_value = self.toml_config.and_then(|config| config.rpc_endpoint_port);
        self.command_args
            .port
            .and_then(|s| s.parse::<u32>().ok())
            .or(toml_value)
            .unwrap_or(DEFAULT_RPC_PORT.parse().unwrap_or_default())
    }
    pub fn user_name(&'a self) -> Option<&'a str> {
        let toml_value = self
            .toml_config
            .and_then(|config| config.rpc_endpoint_user.as_ref())
            .map(|s| s as &str);
        self.command_args.username.or(toml_value)
    }
    pub fn password(&'a self) -> Option<&'a str> {
        let toml_value = self
            .toml_config
            .and_then(|config| config.rpc_endpoint_pass.as_ref())
            .map(|s| s as &str);
        self.command_args.password.or(toml_value)
    }
}

pub struct RedisCommandArgs<'a> {
    pub host: Option<&'a str>,
    pub port: Option<&'a str>,
}

pub struct RedisConfig<'a> {
    pub command_args: RedisCommandArgs<'a>,
    pub toml_config: Option<&'a RedisToml>,
}

impl<'a> RedisConfig<'a> {
    pub fn host(&'a self) -> &'a str {
        let toml_value = self
            .toml_config
            .and_then(|config| config.redis_host.as_ref())
            .map(|s| s as &str);
        self.command_args
            .host
            .or(toml_value)
            .unwrap_or(DEFAULT_REDIS_HOST)
    }
    pub fn port(&'a self) -> u32 {
        let toml_value = self.toml_config.and_then(|config| config.redis_port);
        self.command_args
            .port
            .and_then(|s| s.parse::<u32>().ok())
            .or(toml_value)
            .unwrap_or(DEFAULT_REDIS_PORT.parse().unwrap_or_default())
    }
}

pub struct GeneralCommandArgs<'a> {
    round_duration: Option<&'a str>,
    log_quiet: bool,
    log_level: Option<&'a str>,
    skip_waiting_ibd: bool,
    daemon: bool,
    pid: Option<&'a str>,
    log_file: Option<&'a str>,
}

pub struct GeneralConfig<'a> {
    command_args: GeneralCommandArgs<'a>,
    toml_config: Option<&'a GeneralToml>,
}

impl<'a> GeneralConfig<'a> {
    pub fn round_duration(&'a self) -> u64 {
        let toml_value = self.toml_config.and_then(|config| config.round_duration);
        self.command_args
            .round_duration
            .and_then(|d| d.parse().ok())
            .or(toml_value)
            .unwrap_or(ROUND_INTERVAL_DEFAULT_SECS)
    }
    pub fn log_level(&'a self) -> &'a str {
        let toml_value = self
            .toml_config
            .and_then(|config| config.log_level.as_ref())
            .map(|s| s as &str);
        self.command_args
            .log_level
            .or(toml_value)
            .unwrap_or(DEFAULT_LOG_LEVEL)
    }
    pub fn log_quiet(&'a self) -> bool {
        let toml_value = self
            .toml_config
            .and_then(|config| config.log_quiet)
            .unwrap_or_default();
        self.command_args.log_quiet || toml_value
    }
    pub fn skip_waiting_ibd(&'a self) -> bool {
        let toml_value = self
            .toml_config
            .and_then(|config| config.skip_waiting_ibd)
            .unwrap_or_default();
        self.command_args.skip_waiting_ibd || toml_value
    }
    pub fn daemon(&'a self) -> bool {
        let toml_value = self
            .toml_config
            .and_then(|config| config.daemon)
            .unwrap_or_default();
        self.command_args.daemon || toml_value
    }
    pub fn pid(&'a self) -> &'a str {
        let toml_value = self
            .toml_config
            .and_then(|config| config.pid.as_ref())
            .map(|s| s as &str);
        self.command_args.pid.or(toml_value).unwrap_or(
            DEFAULT_PID
                .to_str()
                .expect("Can't cast default pid PathBuf to &str"),
        )
    }
    pub fn log_file(&'a self) -> &'a str {
        let toml_value = self
            .toml_config
            .and_then(|config| config.log_file.as_ref())
            .map(|s| s as &str);
        self.command_args.log_file.or(toml_value).unwrap_or(
            DEFAULT_LOG_FILE
                .to_str()
                .expect("Can't cast default log file PathBuf to &str"),
        )
    }
}

/// command example:
/// ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e --privatekey=cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA -t 2
impl<'a> CommandArgs<'a> {
    /// constructor.
    /// Basically, search config file as file name signer_config.toml in current dir.
    /// These options can be set by both of from file and command args.
    /// If an option is set by both, then take command args.
    /// If there is not a config file, mandatory params should be passed as command line arguments.
    pub fn new() -> Result<CommandArgs<'static>, crate::errors::Error> {
        CommandArgs::load(get_options().get_matches())
    }

    /// constructor.
    /// create CommandArgs by using specified ArgMatches.
    pub fn load(matches: clap::ArgMatches) -> Result<CommandArgs, crate::errors::Error> {
        // load from config file if exists.
        let config_file = matches.value_of(OPTION_NAME_CONFIG).unwrap();
        match read_config(config_file) {
            Ok(c) => Ok(CommandArgs {
                matches,
                config: Some(c),
            }),
            Err(crate::errors::Error::ConfigFileIOError(ioerror)) => {
                log::warn!("config file read error: {:?}", ioerror);
                Ok(CommandArgs {
                    matches,
                    config: None,
                })
            }
            Err(e) => Err(e),
        }
    }

    pub fn signer_config(&self) -> SignerConfig {
        let threshold_args = self.matches.value_of(OPTION_NAME_THRESHOLD);
        let num: Option<u8> = threshold_args.and_then(|s| s.parse().ok());
        SignerConfig {
            command_args: SignerCommandArgs {
                to_address: self.matches.value_of(OPTION_NAME_TO_ADDRESS),
                public_keys: self
                    .matches
                    .values_of(OPTION_NAME_PUBLIC_KEY)
                    .map(|vs| vs.collect()),
                private_key: self.matches.value_of(OPTION_NAME_PRIVATE_KEY),
                threshold: num,
            },
            toml_config: self.config.as_ref().and_then(|c| c.signer.as_ref()),
        }
    }

    pub fn rpc_config(&self) -> RpcConfig {
        RpcConfig {
            command_args: RpcCommandArgs {
                host: self.matches.value_of(OPTION_NAME_RPC_ENDPOINT_HOST),
                port: self.matches.value_of(OPTION_NAME_RPC_ENDPOINT_PORT),
                username: self.matches.value_of(OPTION_NAME_RPC_ENDPOINT_USER),
                password: self.matches.value_of(OPTION_NAME_RPC_ENDPOINT_PASS),
            },
            toml_config: self.config.as_ref().and_then(|c| c.rpc.as_ref()),
        }
    }

    pub fn redis_config(&self) -> RedisConfig {
        RedisConfig {
            command_args: RedisCommandArgs {
                host: self.matches.value_of(OPTION_NAME_REDIS_HOST),
                port: self.matches.value_of(OPTION_NAME_REDIS_PORT),
            },
            toml_config: self.config.as_ref().and_then(|c| c.redis.as_ref()),
        }
    }
    pub fn general_config(&self) -> GeneralConfig {
        GeneralConfig {
            command_args: GeneralCommandArgs {
                round_duration: self.matches.value_of(OPTION_NAME_REDIS_HOST),
                log_level: self.matches.value_of(OPTION_NAME_LOG_LEVEL),
                log_quiet: self.matches.is_present(OPTION_NAME_LOG_QUIET),
                skip_waiting_ibd: self.matches.is_present(OPTION_NAME_SKIP_WAITING_IBD),
                daemon: self.matches.is_present(OPTION_NAME_DAEMON),
                pid: self.matches.value_of(OPTION_NAME_PID),
                log_file: self.matches.value_of(OPTION_NAME_LOG_FILE),
            },
            toml_config: self.config.as_ref().and_then(|c| c.general.as_ref()),
        }
    }
}

fn read_config(file_path: &str) -> Result<ConfigToml, crate::errors::Error> {
    let contents = std::fs::read_to_string(file_path)?;
    let toml: ConfigToml = toml::from_str(&contents)?;
    Ok(toml)
}

/// command example:
/// ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e --privatekey=cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA -t 2
pub fn get_options<'a, 'b>() -> clap::App<'a, 'b> {
    App::new("node")
        .about("Tapyrus siner node")
        .arg(Arg::with_name(OPTION_NAME_CONFIG)
            .short("c")
            .long("config")
            .value_name("CONFIG_FILE_PATH")
            .default_value(DEFAULT_CONFIG_FILENAME)
            .help("Load settings from this file. when defined both in file and command line args, then command line args take precedence."))
        .arg(Arg::with_name(OPTION_NAME_TO_ADDRESS)
            .long("to_address")
            .value_name("TO_ADDRESS")
            .help("Coinbase pay to address."))
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
        .arg(Arg::with_name(OPTION_NAME_RPC_ENDPOINT_HOST)
            .long("rpchost")
            .value_name("HOST_NAME or IP")
            .help("TapyrusCore RPC endpoint host."))
        .arg(Arg::with_name(OPTION_NAME_RPC_ENDPOINT_PORT)
            .long("rpcport")
            .value_name("PORT")
            .help("TapyrusCore RPC endpoint port number. These are TapyrusCore default port, mainnet: 2377, testnet: 12377, regtest: 12381."))
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
            .help("Redis host."))
        .arg(Arg::with_name(OPTION_NAME_REDIS_PORT)
            .long("redisport")
            .value_name("PORT")
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
            .help("Set the log level."))
        .arg(Arg::with_name(OPTION_NAME_ROUND_DURATION)
            .long("duration")
            .short("d")
            .takes_value(true)
            .value_name("SECs")
            .help("Round interval times(sec)."))
        .arg(Arg::with_name(OPTION_NAME_SKIP_WAITING_IBD)
            .long("skip-waiting-ibd")
            .help("This flag make signer node don't waiting connected Tapyrus full node finishes Initial Block Download when signer node started. When block creation stopped much time, The status of Tapyrus full node changes to progressing Initial Block Download. In this case, block creation is never resume, because signer node waits the status is back to non-IBD. So you can use this flag to start signer node with ignore tapyrus full node status."))
        .arg(Arg::with_name(OPTION_NAME_DAEMON)
            .long("daemon")
            .help("Daemonize the Tapyrus Signer node process."))
        .arg(Arg::with_name(OPTION_NAME_PID)
            .long("pid")
            .takes_value(true)
            .value_name("file")
            .help("Specify pid file path. This option is enable when the node got '--daemon' flag."))
        .arg(Arg::with_name(OPTION_NAME_LOG_FILE)
            .long("logfile")
            .takes_value(true)
            .value_name("file")
            .help("Specify where log file export to. This option is enable when the node fot '--daemon' flag. If not, logs are put on stdout and stderr."))
}

#[test]
fn test_load() {
    let matches = get_options()
        .get_matches_from(vec!["node", "-c=tests/resources/signer_config_sample.toml"]);
    let args = CommandArgs::load(matches);
    assert!(args.is_ok());
    assert!(args.unwrap().config.is_some());
}

#[test]
fn test_allow_no_exists_config_file() {
    let matches = get_options().get_matches_from(vec!["node", "-c=hoge.toml"]);
    let args = CommandArgs::load(matches);
    assert!(args.is_ok());
    assert!(args.unwrap().config.is_none());
}

#[test]
#[should_panic(expected = "InvalidTomlFormat")]
fn test_invalid_format_config_file() {
    let matches =
        get_options().get_matches_from(vec!["node", "-c=tests/resources/invalid_format.toml"]);
    let _args = CommandArgs::load(matches).unwrap();
}

#[test]
fn test_load_from_file() {
    let matches = get_options()
        .get_matches_from(vec!["node", "-c=tests/resources/signer_config_sample.toml"]);
    let args = CommandArgs::load(matches).unwrap();
    let pubkeys = args.signer_config().public_keys();
    assert_eq!(pubkeys.len(), 3);
    assert_eq!(
        pubkeys[0].to_string(),
        "033cfe7fa1be58191b9108883543e921d31dc7726e051ee773e0ea54786ce438f8"
    );
    assert_eq!(
        pubkeys[1].to_string(),
        "020464074b94702e9b07803d247021943bdcc1f8700b92b66defb7fadd76e80acf"
    );
    assert_eq!(
        pubkeys[2].to_string(),
        "02cbe0ad70ffe110d097db648fda20bef14dc72b5c9979c137c451820c176ac23f"
    );

    let threshold = args.signer_config().threshold();
    assert_eq!(threshold, 2);

    let privkey = args.signer_config().private_key();
    assert_eq!(
        privkey.to_wif(),
        "cMtJPWz8D1KmTseJa778nWTS93uePrrN5FtUARUZHu7RsjuSTjGX"
    );

    // rpc parameters are loaded from toml data.
    assert_eq!(args.rpc_config().host(), "localhost");
    assert_eq!(args.rpc_config().port(), 12381);
    assert_eq!(args.rpc_config().user_name(), Some("user"));
    assert_eq!(args.rpc_config().password(), Some("pass"));

    // redis parameters are loaded from toml data.
    assert_eq!(args.redis_config().host(), "192.168.0.63");
    assert_eq!(args.redis_config().port(), 16379);

    // general parameters are loaded from toml data.
    assert_eq!(args.general_config().round_duration(), 5);
    assert_eq!(args.general_config().log_level(), "debug");
    assert_eq!(args.general_config().log_quiet(), true);
    assert_eq!(args.general_config().daemon(), true);
    assert_eq!(args.general_config().pid(), "/tmp/tapyrus-signer.pid");
    assert_eq!(
        args.general_config().log_file(),
        "/var/log/tapyrus-signer.log"
    );
}

#[test]
fn test_priority_commandline() {
    let matches = get_options().get_matches_from(vec![
        "node",
        "-c=tests/resources/signer_config.toml",
        "-p=020464074b94702e9b07803d247021943bdcc1f8700b92b66defb7fadd76e80acf",
        "-p=033cfe7fa1be58191b9108883543e921d31dc7726e051ee773e0ea54786ce438f8",
        "--threshold=1",
        "--privatekey=L4Bw5GTJXL7Nd5wjprXim2sMpNgTSieZ14FCaHax7zzRnHbx19sc",
        "--rpchost=tapyrus.dev.chaintope.com",
        "--rpcport=12345",
        "--rpcuser=test",
        "--rpcpass=test",
        "--redishost=redis.endpoint.dev.chaintope.com",
        "--redisport=88888",
        "--daemon",
        "--pid=/tmp/test.pid",
        "--logfile=/tmp/tapyrus-signer.log",
    ]);
    let args = CommandArgs::load(matches).unwrap();
    let pubkeys = args.signer_config().public_keys();
    assert_eq!(pubkeys.len(), 2);
    assert_eq!(
        pubkeys[0].to_string(),
        "020464074b94702e9b07803d247021943bdcc1f8700b92b66defb7fadd76e80acf"
    );
    assert_eq!(
        pubkeys[1].to_string(),
        "033cfe7fa1be58191b9108883543e921d31dc7726e051ee773e0ea54786ce438f8"
    );
    let threshold = args.signer_config().threshold();
    assert_eq!(threshold, 1);

    let privkey = args.signer_config().private_key();
    assert_eq!(
        privkey.to_wif(),
        "L4Bw5GTJXL7Nd5wjprXim2sMpNgTSieZ14FCaHax7zzRnHbx19sc"
    );

    // rpc parameters are loaded from toml data.
    assert_eq!(args.rpc_config().host(), "tapyrus.dev.chaintope.com");
    assert_eq!(args.rpc_config().port(), 12345);
    assert_eq!(args.rpc_config().user_name(), Some("test"));
    assert_eq!(args.rpc_config().password(), Some("test"));

    // redis parameters are loaded from toml data.
    assert_eq!(
        args.redis_config().host(),
        "redis.endpoint.dev.chaintope.com"
    );
    assert_eq!(args.redis_config().port(), 88888);

    assert_eq!(args.general_config().daemon(), true);
    assert_eq!(args.general_config().pid(), "/tmp/test.pid");
    assert_eq!(args.general_config().log_file(), "/tmp/tapyrus-signer.log");
}

#[test]
#[should_panic(
    expected = "\\'aaaa\\' is invalid public key format.\\n\\'bbbb\\' is invalid public key format.\\n"
)]
fn test_invid_pubkeys() {
    let matches = get_options().get_matches_from(vec![
        "node",
        "-c=tests/resources/signer_config.toml",
        "-p=aaaa",
        "-p=bbbb",
    ]);
    let args = CommandArgs::load(matches).unwrap();
    let _pubkeys = args.signer_config().public_keys();
}

#[test]
#[should_panic(expected = "Must be specified public_keys.")]
fn test_no_pubkeys() {
    let matches = get_options().get_matches_from(vec!["node"]);
    let args = CommandArgs {
        matches,
        config: Some(ConfigToml::default()),
    };
    let _pubkeys = args.signer_config().public_keys();
}

#[test]
#[should_panic(expected = "Must be specified threshold.")]
fn test_no_thrshold() {
    let matches = get_options().get_matches_from(vec!["node"]);
    let args = CommandArgs {
        matches,
        config: Some(ConfigToml::default()),
    };
    let _threshold = args.signer_config().threshold();
}

#[test]
#[should_panic(expected = "Must be specified private_key.")]
fn test_no_private_key() {
    let matches = get_options().get_matches_from(vec!["node"]);
    let args = CommandArgs {
        matches,
        config: Some(ConfigToml::default()),
    };
    let _privkey = args.signer_config().private_key();
}

#[test]
#[should_panic(expected = "'aabbccdd' is invalid WIF format!. error msg:")]
fn test_invalid_private_key() {
    let matches = get_options().get_matches_from(vec!["node"]);
    let args = CommandArgs {
        matches,
        config: Some(ConfigToml {
            signer: Some(SignerToml {
                to_address: None,
                publickeys: None,
                threshold: Some(0),
                privatekey: Some("aabbccdd".to_string()),
            }),
            ..ConfigToml::default()
        }),
    };
    let _privkey = args.signer_config().private_key();
}

#[test]
#[should_panic(expected = "'aabbccdd' is invalid address. error msg:")]
fn test_invalid_to_address() {
    let matches = get_options().get_matches_from(vec!["node"]);
    let args = CommandArgs {
        matches,
        config: Some(ConfigToml {
            signer: Some(SignerToml {
                to_address: Some("aabbccdd".to_string()),
                publickeys: None,
                threshold: Some(0),
                privatekey: None,
            }),
            ..ConfigToml::default()
        }),
    };
    let _to_address = args.signer_config().to_address();
}

#[test]
#[should_panic(expected = "Network should be same among with to_address and WIF of private_key")]
fn test_invalid_network_among_with_to_address_and_private_key() {
    let matches = get_options().get_matches_from(vec!["node"]);
    let args = CommandArgs {
        matches,
        config: Some(ConfigToml {
            signer: Some(SignerToml {
                to_address: Some("mkWk6dDtB6A1UtenWN3W24osVmbsyYD2oM".to_string()),
                publickeys: None,
                threshold: Some(0),
                privatekey: Some(
                    "KzEdPiFuaQktBK8WdsbuzXARzzyJ9uZWB9dnq78UF17Pe1fra33P".to_string(),
                ),
            }),
            ..ConfigToml::default()
        }),
    };
    let _to_address = args.signer_config().to_address();
}
