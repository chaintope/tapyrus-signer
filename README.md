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

Here, we build a Tapyrus Signer Network that can generate a block if 2 of 3 signers agree. 
(Current implementation has an [issue](https://github.com/chaintope/tapyrus-signer/issues/29) for that threshold process.)
For build this network, there are following steps. 

#### 1. Generate singing keys.

There are 3 signers named Alice, Bob, Carol. Each signer needs own private key and public key on secp256k1 elliptic curve.

Here we use below key pairs. Don't use these keys for serious use.

```
Key pair for Alice:
private key: 53f0d2efbc1e6aae7bcfc762a20a3df0b700cf9808dbdc0855dca6481486ed61
WIF: cQPsVjpiP35ceNqLWDohBdnxedsMzCoX3NFaiSjYvSyFysNEKyBt
public key: 0341c6dc48817c840e17428c50cc9fe71802a2d3a2a36519f63dabc10b5713acf2

Key pair for Bob:
private key: ad11db5745d909cf5bb769fe45acdd435884637fb1fca2cfb6e212deff62fe17
WIF: cTP8JDfEp6s7UYnyexESXSMYi3XSmxRCxS4wFbYwU5eMgvC1kHXk
public key: 03cf6ababa85c0687f1d04bb3446ad24da879519f72ef037e900667cc3cdf1e904

Key pair for Carol:
private key: 74431a3cdb2cc82dfc32a691d9f7e68da7675ba81e6833e00d744169d74faae6 
WIF: cRUhZ5WxmiJ5f87gFoztWRztUwSk7cTfRick4z2Qg7zJnZjdnuJj
public key: 02d7facf8f7b3182dc03d5888fdf78cc5c2d0a5ce14559ffbaa3bab9f86272c591
```

#### 2. Create aggregated key pair.

In general, private Key is confidential. Essentially, such a data as a private key should not be exist in real Tapyrus 
Blockchain Network. This key is created only for test temporally. In a future version, it is going not to need to 
generate aggregated private key.

```
private key: 7545c883dd243cabd3b9d7f2c1af01c2fc3db1d929f8127c5a609c041b03551d
WIF: cRWfUjQ27DPx2BQ3WgyFt8qSdjtMtFLS6oeyj1mwPHk4ef4PfaBt
public key: 0366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4b
```

#### 3. Create a payment address what coinbase transaction in the genesis-block pay to.

```
Address: mpuyVwM2YjEMuZKrhtcRkaJxpbqTGAsFHF

Private key: 8637f5a8927d401bcacaa38e9b8b09cab7406936b785570d129367a08e2d9d11
WIF: cS5c3d9MUDKht7PaKs5Wc3oDHSnbjyDtEZLrJK8LEKmTrFnPGADP
Public key: 030fba1efd87aa426f65b979e536eec4626b5e292a9616fe88558560c3a76c3353
```

#### 4. Generate genesis block for this network

We can use `tapyrus-genesis` utility from [Tapyrus Core](https://github.com/chaintope/tapyrus-core).

```
$ tapyrus-genesis -regtest \
                  -address=mpuyVwM2YjEMuZKrhtcRkaJxpbqTGAsFHF \
                  -signblockpubkey=0366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4b \
                  -signblockprivatekey=cRWfUjQ27DPx2BQ3WgyFt8qSdjtMtFLS6oeyj1mwPHk4ef4PfaBt
```

Generated genesis block data is here.
```
010000000000000000000000000000000000000000000000000000000000000000000000c1457ff3e5c527e69858108edf0ff1f49eea9c58d8d37300a164b3b4f8c8c7cef1a2e72770d547feae29f2dd40123a97c580d44fd4493de072416d53331997617b96f05d210366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4b403a4c09253c7b583e5260074380c9b99b895f938e37799d326ded984fb707e91fa4df2e0524a4ccf5fe224945b4fb94784b411a760eb730d95402d3383dd7ffdc01010000000100000000000000000000000000000000000000000000000000000000000000000000000022210366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4bffffffff0100f2052a010000002776a9226d70757956774d32596a454d755a4b72687463526b614a787062715447417346484688ac00000000
```

#### 5. Run Tapyrus Core

Run Tapyrus Core daemon. You can refer Tapyrus Core's [Getting Started document](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/getting_started.md#how-to-start-tapyrus-in-regtest-mode).

#### 6. Run redis

TSN uses redis pub/sub functionality for to relay messages among each signer. We recommend to use Docker.
```
$ docker pull redis:5.0-alpine
$ docker run --name tapyrus-signer-hub -p 6379:6379 redis:5.0-alpine 
```

#### 7. Create config file for each signer.

In this step, we need to create 3 files for each signer like alice.toml, bob.toml, carol.toml. Each file's contents are 
almost same, but private key part should be specify each own private key.
This config assumes tapyrus core allows RPC connection with basic authentication (user name: user, password: pass).

```toml
[signer]
to_address ="mwekxAgQpqQPwD2yUCohhw6NQxpUmXnGsu"
publickeys = [
"0374332fb4ade39e518f8d7146e77a4a9a0715fd0036ef88c402cbcf1f51f9073d",
"0279b2fb0c5122728d9ea040550a3c0d97384ba5d0d52cec227f19d72bb51a6165",
"03309ba18c5c2763dbd35d90c6bb481a508e1f51c9036db8076deb9fdf5090d4da"
]

privatekey = "[SET_OWN_PRIVATE_KEY_WIF]"
threshold = 2

[rpc]
rpc_endpoint_host = "localhost"
rpc_endpoint_port = 12381
rpc_endpoint_user = "user"
rpc_endpoint_pass = "pass"

[redis]
redis_host = "127.0.0.1"
redis_port =  6379

[general]
round_duration = 290
log_level = "trace"
log_file = "/var/log/tapyrus-signer.log"
```   

#### 8. Run signer nodes.

Run signer nodes. All processes should be started at same time.

```
$ tapyrus-signer-node -c alice.toml --skip-waiting-ibd
$ tapyrus-signer-node -c bob.toml --skip-waiting-ibd
$ tapyrus-signer-node -c carol.toml --skip-waiting-ibd
```

If the TSN start well, block will be generated in each 5 minutes(round_duration was set 290s in config file and adding 
10s for actual round communication time limit for it, result is 300s).

Using Tapyrus Core wallet, you can check the balance of issued coins. However there are limitation which block coinbase 
tx's output is not available until generated 100 blocks after the coinbase block generated.   

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

