
use crate::cli::setup::traits::Response;

use crate::errors::Error;

use clap::{App, Arg, ArgMatches, SubCommand, ArgGroup};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, UNIX_EPOCH};
use tapyrus::blockdata::block::XField;

///federation 
///
///USAGE:
///federation [OPTIONS] <change> --height <height> <--aggregated-public-key <aggregated-public-key>|--max-block-size <max-block-size>>
///
///FLAGS:
///    -h, --help       Prints help information
///    -V, --version    Prints version information
///
///OPTIONS:
///    --aggregated-public-key <aggregated-public-key>    aggregated public key of the new federation
///    --max-block-size <max-block-size>                  max block size of the federation
///    --height <height>                                  block height from which the change can be made
///
///ARGS:
///    <change>    register/unregister federation change [possible values: register, unregister]
///
/// 
/// FILE_NAME: 
/// 
//TODO - change directory
#[cfg(debug_assertions)]
const WRITE_DIR: &str = "target/debug/data/";

#[cfg(not(debug_assertions))]
const WRITE_DIR: &str = "target/release/data/";

pub struct RegisterFederationChangeResponse {
    xfield : XField,
    height:  u32,
    timestamp: std::time::Duration,
}

impl RegisterFederationChangeResponse {
    fn new(xfield: XField, height: u32) -> Self {
        RegisterFederationChangeResponse {
            xfield: xfield,
            height: height,
            timestamp: match std::time::SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(n) => n,
                Err(_) => Duration::new(0, 0)
            }
        }
    }
}

impl std::fmt::Display for RegisterFederationChangeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:>010}{}@{:?}", self.height, self.xfield, self.timestamp)
    }
}

impl Response for RegisterFederationChangeResponse {}


pub struct RegisterFederationChangeCommand {}

impl<'a> RegisterFederationChangeCommand {

    pub fn execute(matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {

        let change: &str = matches
            .value_of("change")
            .ok_or(Error::InvalidArgs("register/unregister".to_string()))?;

        let register = match change {
            "register" => true,
            "unregister" => false,
            _ => return Err(Error::InvalidArgs("register/unregister".to_string())),
        };

        let height: u32 = matches
            .value_of("height")
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or(Error::InvalidArgs("height".to_string()))?;

        if height == 0 {
            return Err(Error::InvalidArgs(format!("Height must be greater than 0")));
        }
        
        let xfield_public_key: XField = match matches.value_of("aggregated-public-key") {
                Some(key) =>  match tapyrus::PublicKey::from_str(key) {
                    Ok(public_key) => XField::AggregatePublicKey(public_key),
                    Err(_) =>  XField::None,
                }
                None => XField::None,
            };

        let xfield_max_block_size: XField = match matches.value_of("max-block-size") {
                Some(s) => match s.parse::<u32>() {
                    Ok(x) => XField::MaxBlockSize(x),
                    Err(_) => XField::None,
                }
                None => XField::None,
            };

        let resp: RegisterFederationChangeResponse = match (&xfield_public_key, &xfield_max_block_size) {
            (XField::AggregatePublicKey(_), XField::None) =>
                RegisterFederationChangeResponse::new(xfield_public_key, height),
            (XField::None, XField::MaxBlockSize(_)) =>
                RegisterFederationChangeResponse::new(xfield_max_block_size, height),
            _ => return Err(Error::InvalidArgs(format!("At least one xfield change is expected. Provide either aggregated-public-key or max-block-size"))),
        };

        if register {
            RegisterFederationChangeCommand::register(resp)?;
        }
        else {
            RegisterFederationChangeCommand::unregister(resp)?;
        }

        //empty response
        Ok(Box::new(RegisterFederationChangeResponse::new(XField::None, height)))
    }

    pub fn register(resp:RegisterFederationChangeResponse) -> Result<(), Error>{
        fs::create_dir_all(WRITE_DIR)?;

        let file_path = Path::new(WRITE_DIR).join( format!("federationchange_{:?}.dat", resp.timestamp));
        let mut file = File::create(&file_path)?;
        file.write_all(format!("{}", resp).as_ref())?;
        file.flush()?;

        Ok(())
    }

    pub fn unregister(_resp:RegisterFederationChangeResponse) -> Result<(), Error>{
        //TODO: implement
        Ok(())
    }

    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("federation").args(&[
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
        .group(ArgGroup::with_name("xfield")
            .args(&["aggregated-public-key", "max-block-size"])
            .required(true)
            .multiple(false))
    }
}




#[cfg(test)]

mod tests {
    use super::*;
    use std::fs::DirEntry;
    use std::process::Command;
    use std::fs;
    use std::str;
    use std::path::PathBuf;

    #[cfg(debug_assertions)]
    const DIR: &str = "debug/";

    #[cfg(not(debug_assertions))]
    const DIR: &str = "release/";

    fn check_file(content:String) {
        // Check that the file was created
        let contents = match fs::read_dir(WRITE_DIR) {
            Ok(contents) => contents,
            Err(err) => { panic!("Error: {}", err); }
        };

        let mut found = false;
        // As these tests run in parallel multiple files are created.
        // SO read all files before concluding failure
        for x in contents {
            let entry:DirEntry = match x {
                Ok(e) => e,
                Err(err) => { panic!("Error: {}", err); }
            };
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy().into_owned();

            if file_name_str.starts_with("federationchange_") {
                let file_path = PathBuf::from(WRITE_DIR).join(&file_name);

                let file_contents =  match fs::read_to_string(&file_path){
                    Ok(contents) => contents,
                    Err(err) => {panic!("Error reading file: {}", err);}
                };
                let line:String = match file_contents.parse() {
                    Ok(contents) => contents,
                    Err(err) => {panic!("Error parsing: {}", err);}
                };
                if line.contains(&content) {
                    found = true; break;
                }
                continue;

            }
        }
        if found { return; }
        panic!("File not found");
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
        check_file("00000001000121033e6e1d4ae3e7e1bc2173e2af1f2f65c6284ea7c6478f2241784c77b0dff98e61".to_string());
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
        check_file("000000020002400d0300".to_string());
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
            "InvalidArgs(\"Height must be greater than 0\")"
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
            "InvalidArgs(\"At least one xfield change is expected. Provide either aggregated-public-key or max-block-size\")"
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
            "InvalidArgs(\"At least one xfield change is expected. Provide either aggregated-public-key or max-block-size\")"
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

        // Check that the exit status indicates a failure
        assert!(!output.status.success());

        // Optionally, you can check the output message as well
        let stderr_str = str::from_utf8(&output.stderr).unwrap();
        assert!(stderr_str.contains("cannot be used with one or more of the other specified arguments"));
    }


}