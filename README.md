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
 --rpcport=12381 --rpcuser=user --rpcpass=pass
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

## Verifiable Secret Sharing Scheme

Tapyrus Signer Network(TSN)'s signing algorithm is using [KZen-networks/multi-party-schnorr](https://github.com/KZen-networks/multi-party-schnorr) and it is based on [Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold Scheme for Implicit Certificates](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/provably_secure_distributed_schnorr_signatures_and_a_threshold_scheme.pdf).

If you want to understand what is going on in TSN, We recommend to read section 4 "A (t, n) Threshold Signature Scheme" in the paper before.

## Overview of Tapyrus Signer Network(TSN) How it works

TSN's communication proceeds in two phases below roughly.

1. Network Initialization
2. Block Generation Rounds

### 1. Network Initialization.

This phase corresponds to "Key Generation Protocol" in the paper. In this phase, each signer generates Verifiable Secret 
Shares(VSSs) and commitments from own private key then shares to each other signers. This communication uses 'nodevss' 
message.

After this communication, each signer gets aggregated public key and own share.

### 2. Block Generation Rounds.

After finished Network Initialization, each node can start Block Generation Rounds. Each round has a single Master and 
other Members. The master proposes caididate block and if number of members who agree the proposition met threshold, 
the block is going to be accepted Tapyrus network.

## Message Types

The communication among each node is perform on passing Message which is
boradcasted on Redis pub/sub.

All messages has signer id field which is specify by signer public key.

| Name            | payload | Description                                                  |
| --------------- | ------- | ------------------------------------------------------------ |
| nodevss         | NodeVss | Each signers send VSS in Key Generation Protocol.            |
| candidateblock  | Block   | Round master broadcasts to signer network a candidate block. |
| blockvss        | BlockVSS| Send vss for random secret.                                  |
| blocksig        | LocalSig| Broadcast local sig.                                         |
| completedblock  | Block   | Round master broadcasts completed block.                     |
| roundfailure    |         | Round master notifies the round is failure.                  |


## Round

Signer Network has round. Before start the round, a signer node is elected
round-robin as round master. The master start new round. A round produce
one block if it is succeed.

In following section, it describe communication flow for each master
and member node.

### Round Master Flow

1. Start Next Round
     * Sleep 60 secs. (This is default value. It can be changed by --duration option.)
2. Produce a candidate block
     * Call getnewblock
          * In getnewblock RPC, it test block validity, so we no longer call testproposedblock RPC.
     * Publish new block to all other signers via Redis pub/sub
3. Signature issuing protocol
     * This step has no differences with member process. So describe below.     
4. Submit Block
     * Set signature created in 3.Signature issuing protocol into block header.
     * Call submitblock RPC
     * Publish completed block with completedblock message.
5. Decide Next Master
     * Decide next master node accoding to signer's public keys dictionary order.
     * Start next round as member.

### Round Member Flow

1. Start Next Round
     * Wait for candidateblock message.
2. Check candidate block
     * If the node receives candidateblock message, start to progress.
     * Call testproposedblock RPC
     * If the block is NG, logs warning.
     * If the block is OK, go next step.
3. Signature issuing protocol
     * This step has no differences with member process. So describe below.
4. Waiting completed block
     * Wait for completedblock message. If got, go next step.
5. Decide Next Master
     * When receive completedblock message, decide next master node same way as master flow.
     * Start next round as decided role.

### Signature issuing protocol

1. Sharing VSSs
     * Generate random secret e_i.
     * Calculate own commitments from random polynomial and own secret e_i. 
     * Calculate VSSs for all signers each from random polynomial and each signer index.
     * Send commitments and VSSs to each signer using blockvss message. Especially, master signer should pay attention for each VSS must be sent to correct signer.
     * Receive VSSs from other signers and verify it using commitments.
     * If the number of VSSs met number of signers, go next step.(In paper, it is enough that collecting vss is met threshold, but current implementation is not do that. This behavior is going to be fixed near future.)
2. Sharing local signatures  
     * Calculate own share from VSSs got in "Sharing VSSs".
     * Calculate aggregated public key from commitments which correspond constant term's coefficients
     * Generate local signature from below informations.
          * Two shares which are generated in Key Generation Protocol and previous step.
          * Aggregated public key which is generated in Key Generation Protocol.
          * Temporary aggregated public key which is created in previous step.
          * Sighash which is message of signature. It is hash value of block header except proof field.
     * Broadcast local signature using blocksig message.
     * Receive local signatures from other nodes and verify them.
     * If the number of local signatures met threshold, aggregate final signature and put it in block header .

### About Timeout

Each round need to finish in 65 secs, otherwise the round was fail and start
next round. This mechanism is for availability. Because of timeout, Signer
Network can continue if some signer node stoped.

65 secs is consisted of round duration and actually time limit for round process.
Round duration can be set by `--duration` option. Default is 60 secs.
Time limit is fixed as 5 secs.

## Now is alpha version

Current implementation is not stable. So it has some problems.

### Multi masters in a round appear

Depending on the starting timing some nodes, there are multi master nodes
appear. To avoid this problem, you should use odd number as signer count.

