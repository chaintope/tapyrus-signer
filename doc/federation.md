# Federation Management

This document describes the Federation Management of Tapyrus.

## Overview

The Tapyrus Signer Network is a permitted network consisting of identifiable signers who can control to sign blocks.
These signers cannot only sign blocks but also can control the identity of the participants on the network themselves.
We introduce Federation, which is consisted of a set of identifiable signers and the features to maintain their access controls.

A new signer joining the network needs to get approval from the signers who belongs to the Federation.
Federation, including a new signer, needs to recreate a new Aggregate public key and secret in the same protocol as [How to set up new Tapyrus Signer Network](./setup.md).
The created Aggregate public key is committed by the signer in the existing Federation and submitted to Tapyrus Core with the block.
Block headers have a field for a new Aggregate public key.
When a new Aggregate public key is set in a block header, Tapyrus Core discards the public key that has been used so far and performs proof verification using the new Aggregate public key from the next block.
When leaving from the Federation, it is necessary to update the Aggregate public key in the same protocol.

## How To Update Federation

The following describes how to change the Federation.

### Re-create Aggregate public key and secret.

Federation members, including the new signer, regenerate the Aggregate public key and the secret in the same procedure as [Generate Aggregate public key and Node secret share for Tapyrus-signer network](./setup.md#generate-aggregate-public-key-and-node-secret-share-for-tapyrus-signer-network).
Note that the same node public key can be used for the existing signer, so Step 1 is not required. However, for a new signer, a key pair needs to be created in Step 1.

### Updating the Aggregate public key for existing signers

:heavy_exclamation_mark:Caution: 
> The RPC functionality is not implemented at 0.4.0 release. It is going to be implemented in a future release.
> In 0.4.0 release, you can set federation information into `federations.toml` file directory. If you want to update federations settings, you can update the `federations.toml` and restart tapyrus-signerd.

Update the Aggregate public key held by the existing signer.
For updating, use RPC `update_federation`.

RPC `update_federation` takes the following parameters.

| name         | type                | description                                                                                  |
| ------------ | ------------------- | -------------------------------------------------------------------------------------------- |
| block_height | 32-bits integer     | a block height where the new Federation is applied                                           |
| threshold    | 64-bits integer     | number of signer agreements to sign a block. it must be less than the number of signers.     |
| node_vss     | array of hex string | an array of the Verifiable Secret Sharing. See Appendix A in setup.md                        |

The following is an example of executing `update_federation` using curl.

```
curl -X POST "http://127.0.0.1:3000/update_federation" -H "accept: */*" -H "Content-Type: application/json" -d "{\"method\":\"update_federation\",\"id\":1,\"jsonrpc\":\"2.0\",\"params\":{\"block_height\":99999,\"threshold\":2,,\"node_vss\":[\"03842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca2...\",\"03e568e3a5641ac21930b51f92fb6dd201fb46faae560b108cf3a96380da08dee1...\",\"02a1c8965ed06987fa6d7e0f552db707065352283ab3c1471510b12a76a5905287...\"]}}"
```

And signers who received `update_federation` schedule to update this information in the future block.
The above parameters need to be persisted. If the signer process is restarted after executing `update_federation`, the Federation must be updated without having to execute `update_federation` again.

- Existing signers who belong to the Federation:
  - until they receive an RPC `update_federation` request, which includes public keys of all signers in the new Federation.
    - SHOULD reject any communication from a new signer
  - after they receives a RPC `update_federation`,
    - MAY accept connection requests from the new signer
  - until the applicable block height is reached
    - MUST ignore any messages from the new signer.
  - after the block that applies the federation changes has been submitted into Tapyrus Core,
    - SHOULD disconnect the old signer who is no longer member of the Federation.
    - MUST reject any communication from them.
- New signer:
  - after a federation signer receives an RPC `update_federation`,
    - MAY send a connection request to them.
- Old signer:
  - after the block that applies the federation changes has been submitted into Tapyrus Core,
    - SHOULD disconnect and leave from the Tapyrus Signer Network

### Start new signer and stop leaving signer

The new signer launches tapyrus-signer as described in [How To configure Tapyrus Signer Network](./configuration.md).
The signer MUST complete launching before entering the generation round of the specified block height.
When the signer leaves, they MAY stop the process at any time after the round where the new Federation is applied.

### Send the Aggregate public key to Tapyrus Core.

The round master sent the new Aggregate public key to Tapyrus Core one round before the new Federation is applied.
When starting the previous round, the round master sets a new Aggregate public key to the block and broadcast it to other members of the Federation.
Each member of the round, upon receiving the candidateblock message, verifies that the Aggregate public key is the same as the one expected, and then sign the block.
If the verification is failed, each member SHOULD ignored all messages during that round so that no blocks are generated in that round.
As well as the consensus-building of blocks, the Aggregate public key is valid only if the number of signatures exceeds the threshold t among the existing signers of the Federation.

## Modify or rollback federation plan

The signers of the Federation can check the current and future federation configurations with RPC `show_federation`.

If you change the planned Federation, you need to run `update_federation` again with the same block_height.
If executed with the same `block_height`, the stored Federation will be overwritten.

To cancel the planned Federation, execute `rollback_federation` with block_height.

Federation changes or cancellations must be made before the previous block is generated and submitted to the blockchain.

See [API Specification](./rpc.yaml) for details of the RPC API.