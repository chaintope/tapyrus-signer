# Tapyrus Signer Node
Tapyrus Signer Node is provide and deploy federation signer network.

## Overview
- Communicate each signer node, using redis Pub/Sub.
- Using Tapyrus core for candidate block generation, broadcasting and so on.


## Requirement
Building `node` requires Rust following version.
```
$ rustc --version
rustc 1.41.0 (5e1a79984 2020-01-27)
```
And [Tapyrus-core](https://github.com/chaintope/tapyrus-core/) of latest version for run node.

## Building the Source

Please run bellow command:
```
cargo build --release
```

# Signer Network Specification

Describe about how the signer node communicate with other node.

## SignerID and Signer Index

Each signer nodes are identified by each public keys. And also each nodes
have index. The index is assigned by public keys dictionary order index.
Round master which is describing follow section is decided accoding to
Signer Index.

## Threshold Signature Scheme

Tapyrus Signer Network(TSN)'s signing algorithm bases on "Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold Scheme for Implicit Certificates"[^1].
If you want to understand what is going on in TSN, We recommend reading section 4 "A (t, n) Threshold Signature Scheme" in the paper before.

TSN produces schnorr signatures which is described in [Tapyrus Schnorr Singature Specification](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/schnorr_signature.md)

> [^1]: Stinson, D. R., & Strobl, R. (2001). Provably secure distributed schnorr signatures and a (T, n) threshold scheme for implicit certificates. In Lecture Notes in Computer Science (including subseries Lecture Notes in Artificial Intelligence and Lecture Notes in Bioinformatics) (Vol. 2119, pp. 417–434). Springer Verlag. https://doi.org/10.1007/3-540-47719-5_33

### Verifiable Secret Sharing

The threshold signature scheme uses [Verifiable secret sharing(VSS)](https://en.wikipedia.org/wiki/Verifiable_secret_sharing) inside. And TSN uses [Feldman's scheme](https://en.wikipedia.org/wiki/Verifiable_secret_sharing#Feldman’s_scheme).
The word of VSS appears in this repository means this scheme and sort of data format for VSS scheme.

## Overview of Tapyrus Signer Network(TSN) How it works

After 5 seconds of idling, the block generation round will begin. Each round is divided into roles - one master and 
the other members - with the aim of building consensus on the candidate blocks proposed by the master.

If the agreement among all the signers exceeds the threshold in the round, the block becomes legitimate and is 
broadcast to the Tapyrus blockchain network. Then the next round begins, and block generation continues.

The following describes in detail the messages used to exchange between the signer nodes and the specific algorithms.

## Message Types

The communication among each node is perform on passing Message which is
broadcasted on Redis pub/sub.

All messages has signer id field which is specify by signer public key.

| Message Type      | Payload        | Description                                                  |
| ----------------- | -------------- | ------------------------------------------------------------ |
| candidateblock    | Block          | Round master broadcasts to signer network a candidate block. |
| blockvss          | BlockVSS       | Send vss for random secret.                                  |
| blockparticipants | Vec &lt; PublicKey &gt; | Round master notify `signature issuing protocol` is going to be executed with the signers who are represented in payload keys |
| blocksig          | LocalSig       | Broadcast local sig.                                         |
| completedblock    | Block          | Round master broadcasts completed block.                     |


Caution: Tapyrus-signer is using redis for to relay messages among each node. The word `send` and `broadcast` in the 
descriptions for each message type means logical specification not actual behavior. Actually each node always send 
messages to redis-server and redis relays the messages on pub/sub functionality. When it says `broadcast`, it means a 
message will be sent to a pub/sub channel where subscribed by all nodes. In the other hand, when it says `send`, it 
means a message will be sent to a channel where subscribed by a specific node.

### Structure of payload

All messages are formatted as JSON when it is sent.

#### BlockVSS Structure

BlockVSS has two VSS secrets. The first one is for positive and the other one is for negative.
The word `positive` means that the secret share is generated based on not negated ephemeral key and other one is based 
on negated. 
Why the BlockVSS need to have these two VSS is that k value (which is described in 
[Tapyrus schnorr signature specification](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/schnorr_signature.md#signing-algorithm)) 
must be chosen as y coordinate of R becomes quadratic residue. 

* `Blockvss[0]` Sighash from the candidate block.
* `Blockvss[1]` Object of additional data for the positive VSS.
     * `parameter` Object of secret sharing parameters
          * `threshold` Integer value of threshold - 1.
          * `share_count` Integer value of signer count. (And also it is the number which shares should be created.)
     * `commitments` Array of commitment. A commitment is a point of secp256k1 curve. Which has x and y coordinates.
* `Blockvss[2]` Secret share for *positive*. Hex formatted scalar value of secp256k1 curve.
* `Blockvss[3]` Object of additional data for the negative VSS. The fields are same with positive VSS's one.
* `Blockvss[4]` Secret share for *negative*. Hex formatted scalar value of secp256k1 curve..


*Example*
```json
{
  "Blockvss": [
    "d68e99f1135c6661f174f4bee7c9b94a1e7dbb0eb7609f0aea118340ffd05944",
    {
      "parameters": {
        "threshold": 1,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "1fc491aef36b480160d71b099fe376e58fe0a915d0b382bb2c5daeb2f46665d2",
          "y": "d4ec3f9d4e5a7494447c9f97476abdc475376311e49b7ce6000f9d0640c08fe9"
        },
        {
          "x": "647d33c9bb32320e8b7476743577180021f36e95aa939a96896e7e5be89f08fe",
          "y": "6a68092234664285e4fd244623c406d8feead1e44c1be2b7272f77c733c4ab48"
        }
      ]
    },
    "23a7185d3f2b402ff54168b880da783a7535e55cbc3ad657e5da2f2336cb349c",
    {
      "parameters": {
        "threshold": 1,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "1fc491aef36b480160d71b099fe376e58fe0a915d0b382bb2c5daeb2f46665d2",
          "y": "2b13c062b1a58b6bbb836068b895423b8ac89cee1b648319fff062f8bf3f6c46"
        },
        {
          "x": "4247c04efc03c0c94bb129715d2b8d6128018e607936d9e3075bbb87f411043e",
          "y": "fc8a579ca133a73ad27b0e9499b180c18fe51110beb8ebc90e18d12f2a490f4a"
        }
      ]
    },
    "972ad402adf631e5a52ffe14803a40b19c6f578678a57bc833364842cce9c68"
  ]
}
```


### LocalSig Structure

`BlockSig[0]` Sighash from the candidate block.
`BlockSig[1]` Local signature from a single signer. Final signature will be constructed if count of local signatures met the threshold.
`BlockSig[2]` e of [schnorr signature](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/schnorr_signature.md#signing-algorithm)

*example*
```json
{
  "Blocksig": [
    "d68e99f1135c6661f174f4bee7c9b94a1e7dbb0eb7609f0aea118340ffd05944",
    "218f1a47f87b48fa5ee77202fd14b15dbd04f8ef63834a56c1821f9b4ee842ed",
    "e645628bb53b9902f89771863037e99448069014ab99860b26a3a710a5f746df"
  ]
}
```

## Round

Signer Network has round. Before start the round, a signer node is elected
round-robin as round master. The master start new round. A round produce
one block if it is succeed.

In following section, it describe communication flow for each master
and member node.

### Sequence Diagram

This is sequence diagram for communication among tapyrus-signer nodes. 

[![sequence diagram](https://mermaid.ink/img/eyJjb2RlIjoic2VxdWVuY2VEaWFncmFtXG5BbGljZShNYXN0ZXIpIC0-PiBBbGljZShNYXN0ZXIpOiBzbGVlcCByb3VuZCBkdXJhdGlvblxuTm90ZSBsZWZ0IG9mIEFsaWNlKE1hc3Rlcik6IE1hc3RlciBicm9hZGNhc3Q8YnIvPiBhIGNhbmRpZGF0ZSBibG9ja1xuQWxpY2UoTWFzdGVyKSAtPj4gQm9iOiBjYW5kaWRhdGVibG9ja1xuQWxpY2UoTWFzdGVyKSAtPj4gQ2Fyb2w6IGNhbmRpZGF0ZWJsb2NrXG5cbk5vdGUgbGVmdCBvZiBBbGljZShNYXN0ZXIpOiBBbGwgc2lnbmVycyBzZW5kIHZzczxici8-IHRvIGVhY2ggb3RoZXIuXG5BbGljZShNYXN0ZXIpIC0-PiBCb2I6IGJsb2NrdnNzXG5BbGljZShNYXN0ZXIpIC0-PiBDYXJvbDogYmxvY2t2c3NcbkJvYiAtPj4gQWxpY2UoTWFzdGVyKTogYmxvY2t2c3NcbkJvYiAtPj4gQ2Fyb2w6IGJsb2NrdnNzXG5DYXJvbCAtPj4gQWxpY2UoTWFzdGVyKTogYmxvY2t2c3NcbkNhcm9sIC0-PiBCb2I6IGJsb2NrdnNzXG5cbk5vdGUgbGVmdCBvZiBBbGljZShNYXN0ZXIpOiBNYXN0ZXIgYnJvYWRjYXN0PGJyLz4gcGFydGljaXBhbnRzIGZvciB0aGU8YnIvPiBhZnRlciBmbG93Ljxici8-IEhlcmUgd2UgYXNzdW1lIHRoZSA8YnIvPnBhcnRpY2lwYW50cyBhcmUgQWxpY2U8YnIvPiBhbmQgQm9iLlxuQWxpY2UoTWFzdGVyKSAtPj4gQm9iOiBibG9ja3BhcnRpY2lwYW50c1xuQWxpY2UoTWFzdGVyKSAtPj4gQ2Fyb2w6IGJsb2NrcGFydGljaXBhbnRzXG5cbk5vdGUgbGVmdCBvZiBBbGljZShNYXN0ZXIpOiBFYWNoIHBhcnRpY2lwYW50PGJyLz4gYnJvYWRjYXN0IGJsb2Nrc2lnPGJyLz4gbWVzc2FnZS5cbkFsaWNlKE1hc3RlcikgLT4-IEJvYjogYmxvY2tzaWdcbkFsaWNlKE1hc3RlcikgLT4-IENhcm9sOiBibG9ja3NpZ1xuQm9iIC0-PiBBbGljZShNYXN0ZXIpOiBibG9ja3NpZ1xuQm9iIC0-PiBDYXJvbDogYmxvY2tzaWdcblxuTm90ZSBsZWZ0IG9mIEFsaWNlKE1hc3Rlcik6IE1hc3RlciByZWNvbnN0cnVjdDxici8-IGZpbmFsIHNpZ25hdHVyZSBhbmQ8YnIvPiBzdWJtaXQgdG8gdGhlIFRhcHlydXM8YnIvPiBuZXR3b3JrLjxici8-IFRoZW4sIGJyb2FkY2FzdDxici8-IGNvbXBsZXRlZGJsb2NrPGJyLz4gbWVzc2FnZS5cbkFsaWNlKE1hc3RlcikgLT4-IEJvYjogY29tcGxldGVkYmxvY2tcbkFsaWNlKE1hc3RlcikgLT4-IENhcm9sOiBjb21wbGV0ZWRibG9jayIsIm1lcm1haWQiOnsidGhlbWUiOiJkZWZhdWx0In19)](https://mermaid-js.github.io/mermaid-live-editor/#/edit/eyJjb2RlIjoic2VxdWVuY2VEaWFncmFtXG5BbGljZShNYXN0ZXIpIC0-PiBBbGljZShNYXN0ZXIpOiBzbGVlcCByb3VuZCBkdXJhdGlvblxuTm90ZSBsZWZ0IG9mIEFsaWNlKE1hc3Rlcik6IE1hc3RlciBicm9hZGNhc3Q8YnIvPiBhIGNhbmRpZGF0ZSBibG9ja1xuQWxpY2UoTWFzdGVyKSAtPj4gQm9iOiBjYW5kaWRhdGVibG9ja1xuQWxpY2UoTWFzdGVyKSAtPj4gQ2Fyb2w6IGNhbmRpZGF0ZWJsb2NrXG5cbk5vdGUgbGVmdCBvZiBBbGljZShNYXN0ZXIpOiBBbGwgc2lnbmVycyBzZW5kIHZzczxici8-IHRvIGVhY2ggb3RoZXIuXG5BbGljZShNYXN0ZXIpIC0-PiBCb2I6IGJsb2NrdnNzXG5BbGljZShNYXN0ZXIpIC0-PiBDYXJvbDogYmxvY2t2c3NcbkJvYiAtPj4gQWxpY2UoTWFzdGVyKTogYmxvY2t2c3NcbkJvYiAtPj4gQ2Fyb2w6IGJsb2NrdnNzXG5DYXJvbCAtPj4gQWxpY2UoTWFzdGVyKTogYmxvY2t2c3NcbkNhcm9sIC0-PiBCb2I6IGJsb2NrdnNzXG5cbk5vdGUgbGVmdCBvZiBBbGljZShNYXN0ZXIpOiBNYXN0ZXIgYnJvYWRjYXN0PGJyLz4gcGFydGljaXBhbnRzIGZvciB0aGU8YnIvPiBhZnRlciBmbG93Ljxici8-IEhlcmUgd2UgYXNzdW1lIHRoZSA8YnIvPnBhcnRpY2lwYW50cyBhcmUgQWxpY2U8YnIvPiBhbmQgQm9iLlxuQWxpY2UoTWFzdGVyKSAtPj4gQm9iOiBibG9ja3BhcnRpY2lwYW50c1xuQWxpY2UoTWFzdGVyKSAtPj4gQ2Fyb2w6IGJsb2NrcGFydGljaXBhbnRzXG5cbk5vdGUgbGVmdCBvZiBBbGljZShNYXN0ZXIpOiBFYWNoIHBhcnRpY2lwYW50PGJyLz4gYnJvYWRjYXN0IGJsb2Nrc2lnPGJyLz4gbWVzc2FnZS5cbkFsaWNlKE1hc3RlcikgLT4-IEJvYjogYmxvY2tzaWdcbkFsaWNlKE1hc3RlcikgLT4-IENhcm9sOiBibG9ja3NpZ1xuQm9iIC0-PiBBbGljZShNYXN0ZXIpOiBibG9ja3NpZ1xuQm9iIC0-PiBDYXJvbDogYmxvY2tzaWdcblxuTm90ZSBsZWZ0IG9mIEFsaWNlKE1hc3Rlcik6IE1hc3RlciByZWNvbnN0cnVjdDxici8-IGZpbmFsIHNpZ25hdHVyZSBhbmQ8YnIvPiBzdWJtaXQgdG8gdGhlIFRhcHlydXM8YnIvPiBuZXR3b3JrLjxici8-IFRoZW4sIGJyb2FkY2FzdDxici8-IGNvbXBsZXRlZGJsb2NrPGJyLz4gbWVzc2FnZS5cbkFsaWNlKE1hc3RlcikgLT4-IEJvYjogY29tcGxldGVkYmxvY2tcbkFsaWNlKE1hc3RlcikgLT4-IENhcm9sOiBjb21wbGV0ZWRibG9jayIsIm1lcm1haWQiOnsidGhlbWUiOiJkZWZhdWx0In19)

### Round Master Flow

1. Start Next Round
     * If the round-duration timer is not started
           *  The node starts the timer for counting the round-duration
     * If the round-duration timer is started
           * If the timer is not up
                * If the node receives candidateblock message
                     * The node works as a Member node and leaves this flow.
           * If the timer is up
                * The node goes 2nd step.
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
     * Decide next master node according to signer's public keys dictionary order.
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
     * Send commitments and VSSs to each signer using `blockvss` message. Especially, master signer should pay attention for each VSS must be sent to correct signer.
     * Receive VSSs from other signers and verify it using commitments.
     * If you are Master node, the number of VSSs met number of threshold, go next step.
     * If you are Member node, just wait `blockparticipants` message.
2. Master node declares signers list who can participate after steps
     *  If you are Master node, then broadcast blockparticipants message which represents who can participate Sharing local signature step.
     *  If you are Member node, do nothing. just wait `blockparticipants` message.
3. Sharing local signatures
     * This step must be done by only signers who was designated in `blockparticipants` message. And all participants must have all VSSs from all other participants.
     * Calculate own share from VSSs got in "Sharing VSSs".
     * Calculate temporary aggregated public key from commitments which correspond constant term's coefficients
     * Generate local signature from below information.
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
Network can continue if some signer node stopped.

65 secs is consisted of round duration and actually time limit for round process.
Round duration can be set by `--duration` option. Default is 60 secs.
Time limit is fixed as 5 secs.

## Now is alpha version

Current implementation is not stable. So it has some problems.

### Multi masters in a round appear

Depending on the starting timing some nodes, there are multi master nodes
appear. To avoid this problem, you should use odd number as signer count.
