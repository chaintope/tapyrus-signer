Tapyrus Signer version 0.3.0 is now available for download at: 
  https://github.com/chaintope/tapyrus-signer/releases/tag/v0.3.0/
    
Please report bugs using the issue tracker at github:
  https://github.com/chaintope/tapyrus-signer/issues
  
Project source code is hosted at github; you can get
source-only tarballs/zipballs directly from there:
  https://github.com/chaintope/tapyrus-signer/tarball/v0.3.0  # .tar.gz

0.3.0 change log
-------------------

*Block Signing*

* Upgraded block proof as fixed size Schnorr signature based threshold signature.

*Node Starting Process*

* Support reading options from toml format file.
* Added checking connection to Tapyrus Core RPC endpoint when the node is started. If the Core's in Initial Block 
Download(IBD), signer node is going to wait to finish the IBD. If you don't want to wait, you can use 
`--skip-waiting-ibd` option. 


config file example
-------------------

You can specify signer node options on toml format config file. And you can pass config file path using `-c` option 
like below.

```bash
$ node -c signer.toml
```
 
This is example config file. The specific data are for Tapyrus testnet. You need to modify it to your own environments.  
```toml

[signer]
# You can set configurations for signing process in this `signer` section.
# 
# publickeys = [ ... ]
# `publickeys` is array of public key string. All signers in same signer network have to use same set of public key. 
publickeys = [
"0341c6dc48817c840e17428c50cc9fe71802a2d3a2a36519f63dabc10b5713acf2",
"03cf6ababa85c0687f1d04bb3446ad24da879519f72ef037e900667cc3cdf1e904",
"02d7facf8f7b3182dc03d5888fdf78cc5c2d0a5ce14559ffbaa3bab9f86272c591"
]

# privatekey = "key"
# `privatekey` is Wallet Import Format(WIF) of signer own private key.
privatekey = "put here your secret "

# threshold = 2
# `threshold` is minimum number of signer agreement to generate block signature. it must be less than specified public 
# keys.
threshold = 2

# to_address = "address string"
# `to_address` is address which is going to be set as coinbase tx's pay to address when this signer propose next block.
to_address ="mpuyVwM2YjEMuZKrhtcRkaJxpbqTGAsFHF"

[rpc]
# You can set Tapyrus Core RPC endpoint connection settings here.
rpc_endpoint_host = "hostname or IP"
rpc_endpoint_port = 12377
rpc_endpoint_user = "[user]"
rpc_endpoint_pass = "[password]"

[redis]
# You can set redis endpoint which is going to use to relay messages among each signers.
redis_host = "hostname or IP"
redis_port =  6379

[general]
# Signer node general settings

# Round interval times(sec) in each block signature generation round. 
round_duration = 5 # uint64

# Set the log level. [possible values: error, warn, info, debug, trace]
log_level = "trace"
```