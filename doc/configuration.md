# How To configure Tapyrus Signer Network

This document describes how to configure tapyrus-signer.

After setting up with [How to set up new Tapyrus Signer Network](./setup.md), We can start Tapyrus Signer Network.

`tapyrus-signerd` has two configure files. Both can be specified the path and the name with command line arguments.

* **signer.toml**: This is a configuration file for general purpose to pass the arguments to `tapyrus-sigenrd`.
* **federations.toml**: This is a data file, which hosts federation parameters.

You can set arguments what can be set on signer.toml is also able to set as command line arguments. 
You can get the details of commandline arguments on `-h` option like below:

```
$ tapyrus-signerd -h
node
Tapyrus siner node

USAGE:
    tapyrus-signerd [FLAGS] [OPTIONS]

FLAGS:
        --daemon              Daemonize the Tapyrus Signer node process.
    -h, --help                Prints help information
    -q, --quiet               Silent mode. Do not output logs.
        --skip-waiting-ibd    This flag make signer node don't waiting connected Tapyrus full node finishes Initial
                              Block Download when signer node started. When block creation stopped much time, The status
                              of Tapyrus full node changes to progressing Initial Block Download. In this case, block
                              creation is never resume, because signer node waits the status is back to non-IBD. So you
                              can use this flag to start signer node with ignore tapyrus full node status.
    -V, --version             Prints version information

OPTIONS:
        --to-address <TO_ADDRESS>         Coinbase pay to address.
    -c, --config <CONFIG_FILE_PATH>       Load settings from this file. when defined both in file and command line args,
                                          then command line args take precedence. [default: signer_config.toml]
        --federations-file <FILE>         The path to TOML file of the federations of the chain.
        --log-file <file>                 Specify where log file export to. This option is enable when the node fot
                                          '--daemon' flag. If not, logs are put on stdout and stderr.
    -l, --log <log_level>                 Set the log level. [possible values: error, warn, info, debug, trace]
        --pid <file>                      Specify pid file path. This option is enable when the node got '--daemon'
                                          flag.
    -p, --public-key <PUBLIC_KEY>         Public key of the signer who host this tapyrus-sigenrd. example:
                                          03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc
        --redis-host <HOST_NAME or IP>    Redis host.
        --redis-port <PORT>               Redis port.
    -d, --duration <SECs>                 Round interval times(sec).
        --rpc-host <HOST_NAME or IP>      TapyrusCore RPC endpoint host.
        --rpc-pass <PASS>                 TapyrusCore RPC user password.
        --rpc-port <PORT>                 TapyrusCore RPC endpoint port number. These are TapyrusCore default port,
                                          mainnet: 2377, testnet: 12377, regtest: 12381.
        --rpc-user <USER>                 TapyrusCore RPC user name.
```  

## signer.toml

This configuration file is for general settings about `tapyrus-signerd` process behavior.
This is an example file.

```toml
[signer]
public-key = "033cfe7fa..."
federations-file = "/path/to/federations.toml"

[rpc]
rpc-endpoint-host = "127.0.0.1"
rpc-endpoint-port = 2377
rpc-endpoint-user = "user"
rpc-endpoint-pass = "pass"

[redis]
redis-host = "127.0.0.1"
redis-port =  6379

[general]
round-duration = 5
log-quiet = true
log-level = "info"
daemon = true
pid = "/path/to/tapyrus-signer.pid"
log-file = "/path/to/tapyrus-signer.log"
```

Here describe each item above.

### [general] section

`[general]` section is a set of settings for application.

* `round-duration` is round robin duration time(sec).
This is optional, default duration is 60 sec.
if you want more slowly or quickly block creation, then set more big/small duration time.
* `log-quiet` is setted `true` to silent of log report.
This is optional, default false
* `log-level` is Log Level.
selectable values are `trace`, `debug`, `info`, `warn` or `error`.
This is optional, default value `info`.
* `daemon` is flag for to run node as daemon process. Set true then the node run as daemon.
* `pid`
Specify pid file path. This option is enable when the node got '--daemon' flag.
* `log-file`
Specify where log file export to. This option is enable when the node got '--daemon' flag.
If not, logs are put on stdout and stderr.

### [signer] section

`[signer]` section is a set of settings for consensus algorithm used in Tapyrus Signer/Core Network.

* `public-key`
This is required. This is specify the signer own public key who hosted the node.
This is require and public key format is compressed hex string.
* `federations-file`
This is required. This is specify the path to TOML file of the federations of the chain.

### [rpc] section

`[rpc]` section is a set of settings for rpc connection to Tapyrus Core node.

* `rpc-endpoint-host`
This is optional.
TapyrusCore RPC endpoint host name. The default value is `127.0.0.1`.
* `rpc-endpoint-port`
This is optional. 
This is TapyrusCore RPC endpoint port number.
The default is `2377` (production chain).
Tapyrus-Core default RPC ports is here. 
For production chain: `2377`. For development chain: `12381`.
* `rpc-endpoint-user`
This is optional.
This is TapyrusCore RPC user name for authentication.
require if you set username to your TapyrusCore RPC Server.
There is no default value.
* `rpc-endpoint-pass`
This is optional.
This is TapyrusCore RPC password for authentication.
require if you set password to your TapyrusCore RPC Server.
There is no default value.

### [redis] seciton

`[redis]` section is a set of settings for redis connection.

* `redis-host`
This is optional. 
This is Redis Server host name or IP Address.
The default value is `127.0.0.1`.
* `redis-port` 
This is optional.
This is Redis Server port number which tapyrus-sigenrd want to connect to. 
The default value is `6379`.

## federations.toml

This file is a data file for federation parameters. 
You must put federation parameters into this file when you want to startup tapyrs-signerd.
And you must set the path to `federations.toml` as `federations-file` argument.
You can use following way to specify the path.
* `--federations-file` commandline argument 
* `federations-file` item in `[signer]` section on `signer.toml`.

This is an example. Which has two federation parameters. 
The scenario of this case is that the chain starts with first federation parameters whose `block-height` is 0.
Then the chain would change the federation to second one from 100 block height. 

```toml
[[federation]]
block-height = 0
threshold = 3
aggregated-public-key = "030d856ac..."
node-vss = [
  "02472012cf49fca573ca...",
  "02785a891f323acd6cef...",
  "02ce7edc292d7b747fab...",
  "02d111519ba1f3013a7a...",
  "03831a69b8009833ab5b..."
]

[[federation]]
block-height = 100
threshold = 2
aggregated-public-key = "030acd6af9..."
node-vss = [
  "02472012cf49fca573ca...",
  "02ce7edc292d7b747fab...",
  "03831a69b8009833ab5b..."
]
```

Here is descriptions for each item.

* `block-height`
This is required.
This is the block height where the federation would be enabled. 
Tapyrus Signer Network(TSN) produce a block which has Aggregate public key in their xfield when the height of the block is one before of the federation block height.
There is an exception, which is a genesis block. A genesis block always has Aggregate public key.
* `threshold`
This is optional.
This is the threshold the federation requires what number of agreements to produce block proofs.
The threshold must be grater than and equal to two three of federation members count. 
This item should not specify, if the signer is not member of the federation.
* `aggregated-public-key`
This is required.
This is the public key, which can be use to verify block proofs.
This public key is aggregate of all federation member's public keys.  
* `node-vss`
This is optional.
Verifiable Secret Share and commitments from all signers in the federation.
This field may be empty when the signer is not a member of the federation.
This item should not specify , if the signer is not member of the federation.
See also [Tapyrus signer network paramters](doc/setup.md#tapyrus-signer-network-paramters).

Here describe some `federations.toml` examples for particular scenarios.

### Scenario 1: The signer is a member of first federation of the chain.

The signers who are a member of first federation of the chain must set the first federation parameters into their `federations.toml`.
If the federation has 5 members, and the threshold is 3, then the `federations.toml` would be like below.

```toml
[[federation]]
block-height = 0
threshold = 3
aggregated-public-key = "030d856ac..."
node-vss = [
  "02472012cf49fca573ca...",
  "02785a891f323acd6cef...",
  "02ce7edc292d7b747fab...",
  "02d111519ba1f3013a7a...",
  "03831a69b8009833ab5b..."
]
```

If you don't have Node VSSs and Aggregate public key, you should follow steps in [Generate Aggregate public key and Node secret share for Tapyrus-signer network](doc/setup.md#generate-aggregate-public-key-and-node-secret-share-for-tapyrus-signer-network)

## Scenario 2: The signer is out of the federation member from future block height.

Here assume current block height of the chain tip is somewhere among 0 to 98.
The signer is a member of current federation.
The federation is scheduled to transition to the new federation from 100 height.

```toml
[[federation]]
block-height = 0
threshold = 3
aggregated-public-key = "030d856ac..."
node-vss = [
  "02472012cf49fca573ca...",
  "02785a891f323acd6cef...",
  "02ce7edc292d7b747fab...",
  "02d111519ba1f3013a7a...",
  "03831a69b8009833ab5b..."
]

[[federation]]
block-height = 100
aggregated-public-key = "030acd6af9..."
```

After generate 99 height block proof, the signer can stop own tapyrus-signerd.

## Scenario 3: The signer joins the federation from future block height.

Here assume current block height of the chain tip is somewhere among 0 to 98.
The signer is not a member of current federation.
The federation is scheduled to transition to the new federation from 100 height.

```toml
[[federation]]
block-height = 0
aggregated-public-key = "030d856ac..."

[[federation]]
block-height = 100
threshold = 2
aggregated-public-key = "030acd6af9..."
node-vss = [
  "02472012cf49fca573ca...",
  "02ce7edc292d7b747fab...",
  "03831a69b8009833ab5b..."
]
```

Before generate 99 height block proof, you should startup your tapyrus-signerd daemon. 

If you don't have Node VSSs and Aggregate public key for the federation you would join, you should follow steps in [Generate Aggregate public key and Node secret share for Tapyrus-signer network](doc/setup.md#generate-aggregate-public-key-and-node-secret-share-for-tapyrus-signer-network)

## Scenario 4: The signer is a member of the current federation and would be a member of the changed federation in future height.

Here assume current block height of the chain tip is somewhere among 0 to 98.
The signer is a member of current federation.
The federation is scheduled to transition to the new federation from 100 height.
The signer is a member of the next federation.

```toml
[[federation]]
block-height = 0
threshold = 3
aggregated-public-key = "030d856ac..."
node-vss = [
  "02472012cf49fca573ca...",
  "02785a891f323acd6cef...",
  "02ce7edc292d7b747fab...",
  "02d111519ba1f3013a7a...",
  "03831a69b8009833ab5b..."
]

[[federation]]
block-height = 100
threshold = 2
aggregated-public-key = "030acd6af9..."
node-vss = [
  "02472012cf49fca573ca...",
  "02ce7edc292d7b747fab...",
  "03831a69b8009833ab5b..."
]
``` 

If you don't have Node VSSs and Aggregate public key for the new federation, you should follow steps in [Generate Aggregate public key and Node secret share for Tapyrus-signer network](doc/setup.md#generate-aggregate-public-key-and-node-secret-share-for-tapyrus-signer-network)

## Start Signer Node

To start Tapyrus Signer process,

```
/path/to/bin/tapyrus-signerd -c /path/to/signer.toml
```
