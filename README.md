# Tapyrus Signer Node
Tapyrus Signer Node is provide and deploy federation signer network.

## Overview
- Communicate each signer node, using redis Pub/Sub.
- Using Tapyrus core for candidate block generationg, broadcasting and so on.


## Requirement
Building `node` requires Rust following version.
```
stable-x86_64-apple-darwin (default)
rustc 1.35.0 (3c235d560 2019-05-20)
```
And [Tapyrus-core](https://bitbucket.org/chaintope/tapyrus-core/src/master/) of latest version for run node.

## Building the Source

Please run bellow command:
```
cargo build --release
```

### Run Manually
 
Example command option for launch one of node in 3 of 5 Signer network.

Must launch `tapyrus-core` and `redis` ahead.

Example for run `tapyrus-core`:
```
-regtest
-debug
-rpcuser=user
-rpcpassword=pass
-signblockpubkeys=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506
-signblockthreshold=3
```

and example for run `tapyrus signer node`:
```
./target/release/node \
 -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc \
 -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 \
 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e \
 -p=02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c \
 -p=02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506 \
 --privatekey=<private key that the pair of one of above publickeys> \
 -t 3 \
 --rpcport=12381 --rpcuser=user --rpcpass=pass
```

Example for If launch as master node.
```
./target/release/node \
 -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc \
 -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 \
 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e \
 -p=02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c \
 -p=02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506 \
 --privatekey=<private key that the pair of one of above publickeys> \
 -t 3 \
 --rpcport=12381 --rpcuser=user --rpcpass=pass \
 --master
```
And helpful comment is in `src/test_helper.rs`.

You can find all command options in `src/bin/node.rs`.
