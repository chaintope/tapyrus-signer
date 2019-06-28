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

# Signer Network Specification

Describe about how the signer node communicate with other node.

## SignerID and Signer Index

Each signer nodes are identified by each public keys. And also each nodes
have index. The index is assigned by public keys dictionary order index.
Round master which is describing follow section is decided accoding to
Signer Index.

## Message Types

The communication among each node is perform on passing Message which is
boradcasted on Redis pub/sub.

All messages has signer id field which is specify by signer public key.

Name | payload | Description
-----|--------|------------
candidateblock | Block | Round master publish candidate block.
signature | Signature | Each signer publish signature.
completedblock | Block | Round master node publishes completed block.
roundfailure |  | Round master notify the round is failure and go next round.

## Round

Signer Network has round. Before start the round, a signer node is elected
round-robin as round master. The master start new round. A round produce
one block if it is succeed.

In following section, it describe communication flow for each master
and member node.

### Round Master Flow

1. Start Next Round
     * Sleep 60 secs.
2. Produce a candidate block
     * Call getnewblock
          * In getnewblock RPC, it test block validity, so we no longer call testproposedblock RPC.
     * Publish new block to all other signers via Redis pub/sub
3. Collect signatures
     * Create own signature for the candidate block.
     * Collect valid signatures form other members via signatures message.
     * If threshold is met, go through next step.
     * If 10sec passed or NG message count is over the signers count minus threshold(that is never met the threshold), publish failureround message and finish this round.
4. Submit Block
     * Call combineblocksigs RPC
     * Call submitblock RPC
     * Publish completed block to completedblock message.
5. Decide Next Master
     * Decide next master node accoding to signer's public keys dictionary order.
     * Start next round as member.

### Round Member Flow

1. Start Next Round
     * Wait for candidateblock message.
2. Check & Sign block
     * If the node receives candidateblock message, start to progress.
     * Call testproposedblock RPC
     * If the block is NG, logs warning.
     * If the block is OK, create signature.
3. Publish signature
     * Publish signature using signature message.
     * Wait for completedblock message.
4. Decide Next Master
     * When receive completedblock message, decide next master node same way as master flow.
     * Start next round as decided role.

### About Timeout

Each round need to finish in 65 secs, otherwise the round was fail and start
next round. This mechanism is for availability. Because of timeout, Signer
Network can continue if some signer node stoped.

## Now is alpha version

Current implementation is not stable. So it has some problems.

### Multi masters in a round appear

Depending on the starting timing some nodes, there are multi master nodes
appear. To avoid this problem, you should use odd number as signer count.

