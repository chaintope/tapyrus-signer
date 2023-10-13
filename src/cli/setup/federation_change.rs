use crate::cli::setup::traits::Response;

use crate::errors::Error;

use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use tapyrus::blockdata::block::XField;

//federation command is used to register/unregister federation change.
// When register is invoked it writes a new file with the given parameters.
// When unregister is invoked it removes the file with the given parameters.
//
// FILE_NAME: federationchange_<timestamp>.dat"
// PATH: FEDERATION_CHANGE_FILE
//
//USAGE:
//federation [OPTIONS] <change> --height <height> <--aggregated-public-key <aggregated-public-key>|--max-block-size <max-block-size>>
//
//FLAGS:
//    -h, --help       Prints help information
//    -V, --version    Prints version information
//
//OPTIONS:
//    --aggregated-public-key <aggregated-public-key>    aggregated public key of the new federation
//    --max-block-size <max-block-size>                  max block size of the federation
//    --height <height>                                  block height from which the change can be made
//
//ARGS:
//    <change>    register/unregister federation change [possible values: register, unregister]
//

lazy_static! {
    static ref FEDERATION_CHANGE_FILE: PathBuf = {
        #[cfg(not(test))]
        {
            let home: String = std::env::var("HOME").expect("Failed to get home directory");
            PathBuf::from(&home)
                .join(".tapyrus_signer")
                .join("federationchange.dat")
        }
        #[cfg(test)]
        {
            PathBuf::from("./target/federationchange_test.dat")
        }
    };
}

//hex encoding of height is 8 bytes
const HEIGHT_STRING_LEN: usize = 8;

lazy_static! {
    static ref FILE_LOCK: Mutex<()> = Mutex::new(());
}

#[derive(Clone)]
pub struct RegisterFederationChangeResponse {
    height: u32,
    xfield: XField,
}

impl std::fmt::Display for RegisterFederationChangeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            //<8 bytes height><xfield(1 byte xfieldtype + xfield value)>
            "{:>0len$x}{}",
            self.height,
            self.xfield,
            len = HEIGHT_STRING_LEN,
        )
    }
}

impl RegisterFederationChangeResponse {
    pub fn from_str(s: &str) -> Result<Self, Error> {
        let height_str = &s[0..HEIGHT_STRING_LEN];
        let height = u32::from_str_radix(height_str, 16)
            .map_err(|_| Error::RegisterFederationError("Failed to parse height".to_string()))?;

        let xfield = s[HEIGHT_STRING_LEN..].to_string();
        let xfield = XField::from_str(xfield.as_str())
            .map_err(|_| Error::RegisterFederationError("Failed to parse xfield".to_string()))?;
        Ok(Self { height, xfield })
    }

    fn new(xfield: XField, height: u32) -> Self {
        RegisterFederationChangeResponse {
            xfield: xfield,
            height: height,
        }
    }
}

impl Response for RegisterFederationChangeResponse {}

pub struct RegisterFederationChangeCommand {}

impl<'a> RegisterFederationChangeCommand {
    pub fn execute(matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {
        let change: &str = matches
            .value_of("change")
            .ok_or(Error::RegisterFederationError(
                "register/unregister".to_string(),
            ))?;

        let register = match change {
            "register" => true,
            "unregister" => false,
            _ => {
                return Err(Error::RegisterFederationError(
                    "register/unregister".to_string(),
                ))
            }
        };

        let height: u32 = matches
            .value_of("height")
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or(Error::RegisterFederationError("height".to_string()))?;

        if height == 0 {
            return Err(Error::RegisterFederationError(format!(
                "Height must be greater than 0"
            )));
        }

        let xfield_public_key: XField = match matches.value_of("aggregated-public-key") {
            Some(key) => match tapyrus::PublicKey::from_str(key) {
                Ok(public_key) => match public_key.compressed {
                    true => XField::AggregatePublicKey(public_key),
                    false => {
                        return Err(Error::RegisterFederationError(format!(
                            "aggregated-public-key was not compressed"
                        )))
                    }
                },
                Err(_) => {
                    return Err(Error::RegisterFederationError(format!(
                        "aggregated-public-key was invalid"
                    )))
                }
            },
            None => XField::None,
        };

        let xfield_max_block_size: XField = match matches.value_of("max-block-size") {
            Some(s) => match s.parse::<u32>() {
                Ok(x) => XField::MaxBlockSize(x),
                Err(_) => {
                    return Err(Error::RegisterFederationError(format!(
                        "max-block-size was invalid"
                    )))
                }
            },
            None => XField::None,
        };

        let resp: RegisterFederationChangeResponse = match (&xfield_public_key, &xfield_max_block_size) {
            (XField::AggregatePublicKey(_), XField::None) =>
                RegisterFederationChangeResponse::new(xfield_public_key, height),
            (XField::None, XField::MaxBlockSize(_)) =>
                RegisterFederationChangeResponse::new(xfield_max_block_size, height),
            _ => return Err(Error::RegisterFederationError(format!("At least one xfield change is expected. Provide either aggregated-public-key or max-block-size"))),
        };

        if register {
            RegisterFederationChangeCommand::register(resp.clone())?;
        } else {
            RegisterFederationChangeCommand::unregister(resp.clone())?;
        }

        //empty response
        Ok(Box::new(resp))
    }

    pub fn register(resp: RegisterFederationChangeResponse) -> Result<(), Error> {
        // mutex to protect file access until register completes.
        let _guard = FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let file_path = Path::new(&*FEDERATION_CHANGE_FILE);

        let mut xfield_changes = Vec::new();

        if !file_path.exists() {
            //create file
            if let Some(parent) = FEDERATION_CHANGE_FILE.parent() {
                if fs::create_dir_all(parent).is_ok() {
                    fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .open(&*FEDERATION_CHANGE_FILE)
                        .map_err(|e| {
                            Error::RegisterFederationError(format!("Failed to open file: {}", e))
                        })?;
                }
            }
        } else {
            //open if it exists
            let file = File::open(&file_path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                match line.len() {
                    0 => break,
                    _ => {
                        if line.len() < HEIGHT_STRING_LEN {
                            return Err(Error::RegisterFederationError(format!(
                                "Invalid line: {}",
                                line
                            )));
                        }
                        match RegisterFederationChangeResponse::from_str(&line) {
                            Ok(field) => xfield_changes.push(field),
                            Err(e) => {
                                return Err(Error::RegisterFederationError(format!(
                                    "Failed to parse line: {}. Error: {}",
                                    line, e
                                )))
                            }
                        }
                    }
                }
            }
        }

        // sort xfield changes by height
        xfield_changes.push(resp);
        xfield_changes.sort_by(|a, b| a.height.cmp(&b.height));

        //open the file fresh for writing
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(file_path)?;
        let mut writer = std::io::BufWriter::new(file);

        for xfield_change in xfield_changes {
            writeln!(writer, "{}", xfield_change.to_string())?;
        }
        writer.flush()?;

        Ok(())
    }

    pub fn unregister(resp: RegisterFederationChangeResponse) -> Result<(), Error> {
        let _guard = FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        //TODO: implement
        Ok(())
    }

    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("federation")
            .args(&[
                Arg::with_name("change")
                    .required(true)
                    .takes_value(true)
                    .possible_values(&["register", "unregister"])
                    .help("register/unregister federation change"),
                Arg::with_name("height")
                    .long("height")
                    .required(true)
                    .takes_value(true)
                    .display_order(99)
                    .help("block height from which the change can be made"),
                Arg::with_name("aggregated-public-key")
                    .long("aggregated-public-key")
                    .takes_value(true)
                    .display_order(1)
                    .help("aggregated public key of the new federation"),
                Arg::with_name("max-block-size")
                    .long("max-block-size")
                    .takes_value(true)
                    .display_order(2)
                    .help("max block size of the federation"),
            ])
            .group(
                ArgGroup::with_name("xfield")
                    .args(&["aggregated-public-key", "max-block-size"])
                    .required(true)
                    .multiple(false),
            )
    }
}

#[cfg(test)]

fn get_file_debug() -> PathBuf {
    PathBuf::from(&*FEDERATION_CHANGE_FILE)
}

mod tests {
    use crate::errors::Error::RegisterFederationError;

    use super::*;
    use std::path::PathBuf;
    use std::process::Command;
    use std::str;

    #[cfg(debug_assertions)]
    const DIR: &str = "debug/";

    #[cfg(not(debug_assertions))]
    const DIR: &str = "release/";

    fn check_file(file_path: PathBuf, content: String) -> Result<(), Error> {
        // Check that the file was created
        let file = match File::open(&file_path) {
            Ok(file) => file,
            Err(e) => {
                panic!(
                    "Failed to open file:{} due to err :{}",
                    file_path.to_string_lossy(),
                    e
                );
            }
        };

        let reader = BufReader::new(file);

        for line in reader.lines() {
            if line
                .expect(format!("line not found in file {}", file_path.to_string_lossy()).as_str())
                .contains(&content)
            {
                return Ok(());
            }
        }
        Err(RegisterFederationError(format!(
            "content not found {}",
            content
        )))
    }

    #[test]
    fn test_execute_success_unregister() {
        let matches = RegisterFederationChangeCommand::args().get_matches_from(vec![
            "federation",
            "unregister",
            "--aggregated-public-key",
            "033e6e1d4ae3e7e1bc2173e2af1f2f65c6284ea7c6478f2241784c77b0dff98e61",
            "--height",
            "500",
        ]);
        let response = RegisterFederationChangeCommand::execute(&matches);
        assert!(response.is_ok());
    }

    #[test]
    fn test_execute_success_register_pubkey() {
        let matches = RegisterFederationChangeCommand::args().get_matches_from(vec![
            "federation",
            "register",
            "--aggregated-public-key",
            "033e6e1d4ae3e7e1bc2173e2af1f2f65c6284ea7c6478f2241784c77b0dff98e61",
            "--height",
            "100",
        ]);
        let response = RegisterFederationChangeCommand::execute(&matches);
        assert!(response.is_ok());
        let res = check_file(
            get_file_debug(),
            "000000640121033e6e1d4ae3e7e1bc2173e2af1f2f65c6284ea7c6478f2241784c77b0dff98e61"
                .to_string(),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_execute_success_register_maxblockize() {
        let matches = RegisterFederationChangeCommand::args().get_matches_from(vec![
            "federation",
            "register",
            "--max-block-size",
            "200000",
            "--height",
            "200",
        ]);
        let response = RegisterFederationChangeCommand::execute(&matches);
        assert!(response.is_ok());
        let res = check_file(get_file_debug(), "000000c802400d0300".to_string());
        assert!(res.is_ok());
    }

    #[test]
    fn test_execute_fail_register_height() {
        let matches = RegisterFederationChangeCommand::args().get_matches_from(vec![
            "federation",
            "register",
            "--aggregated-public-key",
            "033e6e1d4ae3e7e1bc2173e2af1f2f65c6284ea7c6478f2241784c77b0dff98e61",
            "--height",
            "0",
        ]);
        let response = RegisterFederationChangeCommand::execute(&matches);
        assert!(response.is_err());
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "RegisterFederationError(\"Height must be greater than 0\")"
        );
    }

    #[test]
    fn test_execute_fail_register_pubkey() {
        let matches = RegisterFederationChangeCommand::args().get_matches_from(vec![
            "federation",
            "register",
            "--aggregated-public-key",
            "033e6e1d4ae3e7e1bc2173e2af1f2f65c6284ea7c6478f2241784c77b0dff98e61000000",
            "--height",
            "60",
        ]);
        let response = RegisterFederationChangeCommand::execute(&matches);
        assert!(response.is_err());
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "RegisterFederationError(\"aggregated-public-key was invalid\")"
        );
    }

    #[test]
    fn test_execute_fail_register_maxblocksize() {
        let matches = RegisterFederationChangeCommand::args().get_matches_from(vec![
            "federation",
            "register",
            "--max-block-size",
            "t",
            "--height",
            "700",
        ]);
        let response = RegisterFederationChangeCommand::execute(&matches);
        assert!(response.is_err());
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "RegisterFederationError(\"max-block-size was invalid\")"
        );
    }

    #[test]
    fn test_execute_fail_register_both() {
        let output = Command::new(format!("target/{}/tapyrus-setup", DIR).to_string())
            .arg("federation")
            .arg("register")
            .arg("--aggregated-public-key")
            .arg("033e6e1d4ae3e7e1bc2173e2af1f2f65c6284ea7c6478f2241784c77b0dff98e61")
            .arg("--max-block-size")
            .arg("9000")
            .arg("--height")
            .arg("900")
            .output()
            .expect("failed to execute process");

        assert!(!output.status.success());
        let stderr_str = str::from_utf8(&output.stderr).unwrap();
        assert!(
            stderr_str.contains("cannot be used with one or more of the other specified arguments")
        );
    }

    #[test]
    fn test_execute_success_register_multiple() {
        let matches = RegisterFederationChangeCommand::args().get_matches_from(vec![
            "federation",
            "register",
            "--aggregated-public-key",
            "033e6e1d4ae3e7e1bc2173e2af1f2f65c6284ea7c6478f2241784c77b0dff98e61",
            "--height",
            "1000",
        ]);
        let response = RegisterFederationChangeCommand::execute(&matches);
        assert!(response.is_ok());
        let res = check_file(
            get_file_debug(),
            "000003e80121033e6e1d4ae3e7e1bc2173e2af1f2f65c6284ea7c6478f2241784c77b0dff98e61"
                .to_string(),
        );
        assert!(res.is_ok());

        let matches = RegisterFederationChangeCommand::args().get_matches_from(vec![
            "federation",
            "register",
            "--max-block-size",
            "200000",
            "--height",
            "3000",
        ]);
        let response = RegisterFederationChangeCommand::execute(&matches);
        assert!(response.is_ok());
        let res = check_file(get_file_debug(), "00000bb802400d0300".to_string());
        assert!(res.is_ok());

        let matches = RegisterFederationChangeCommand::args().get_matches_from(vec![
            "federation",
            "register",
            "--max-block-size",
            "1000000",
            "--height",
            "5000",
        ]);
        let response = RegisterFederationChangeCommand::execute(&matches);
        assert!(response.is_ok());
        let res = check_file(get_file_debug(), "000013880240420f00".to_string());
        assert!(res.is_ok());
    }

    #[test]
    fn test_execute_success_register_parallel() {
        //this test writes to $HOME/.tapyrus_signer/federationchange.dat file
        //the file contents are not accessible from test and is not verified.

        let output1 = Command::new(format!("target/{}/tapyrus-setup", DIR).to_string())
            .arg("federation")
            .arg("register")
            .arg("--aggregated-public-key")
            .arg("033e6e1d4ae3e7e1bc2173e2af1f2f65c6284ea7c6478f2241784c77b0dff98e61")
            .arg("--height")
            .arg("300")
            .output()
            .expect("failed to execute process");

        let output2 = Command::new(format!("target/{}/tapyrus-setup", DIR).to_string())
            .arg("federation")
            .arg("register")
            .arg("--max-block-size")
            .arg("800000")
            .arg("--height")
            .arg("400")
            .output()
            .expect("failed to execute process");

        assert!(output1.status.success());
        assert!(output2.status.success());
    }
}
