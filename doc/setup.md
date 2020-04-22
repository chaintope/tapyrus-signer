# How to set up new Tapyrus Signer Network

This document describes how to set up a new Tapyrus Signer Network. This document is a part 
of [How to start a new tapyrus network?](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/getting_started.md#how-to-start-a-new-tapyrus-network-1). 
If you have not checked it yet, we recommend that you check it first.

## Overview

We can set up Tapyrus Signer Network and Tapyrus Core Network with the 'trusted' way described in [How to start tapyrus in dev mode?](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/getting_started.md#how-to-start-tapyrus-in-dev-mode). The trusted setup requires to share each signer's private key with all signers. But each signer in Tapyrus Signer Network should be treated as 'trustless' as well as other blockchain systems.

The following shows the protocol for setting up a signer in a 'trustless' network, which has n-singers and threshold t, which is less than n.

We suppose (or recommend) that all signers can communicate with each other using the efficient and secure protocol providing PFS(perfect forward secrecy)[^1], such as SSL/TLS protocol or Noise Protocol[^2].

[^1]: For more information about PFS, see the section 'D.5.1.7 Cryptoperiod and protection lifetime' in the 'IEEE Standard Specifications for Public-Key Cryptography' [IEEE Standard Specifications for Public-Key Cryptography](https://perso.telecom-paristech.fr/guilley/recherche/cryptoprocesseurs/ieee/00891000.pdf)
[^2]: [The Noise Protocol Framework](http://www.noiseprotocol.org/noise.html)

To support for setting up the Tapyrus Signer Network, we provide a command-line utility `tapyrus-setup`

## Tapyrus signer network parameters
In addition to [Tapyrus network parameters](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/getting_started.md#tapyrus-network-parameters), Tapyrus signer network uses following unique parameters to each tapyrus network.

**Node VSS**  
Node VSS is a sort of Verifiable Secret Share(VSS), which is produced at 4.1 Key Generation Protocol in [the paper](https://doi.org/10.1007/3-540-47719-5_33).
[The structure](#structure-of-vss) is mentioned later.
All signers must have Node VSSs from all signers. The VSSs must include its VSS in federations.toml config file to startup a node.

**Node secret share**
Node secret share is a share that is produced at 4.1 Key Generation Protocol in [the paper](https://doi.org/10.1007/3-540-47719-5_33).
Each signer must have its Node secret share. 
This is calculated by collected Node VSSs.
The value is 32bytes data of private key on secp256k1 curve.

Tapyrus Signer Network uses the following unique parameters to each block generation round.

**Block VSS**
Block VSS is a sort of VSS which is produced at 4.2 Signature Issuing Protocol in [the paper](https://doi.org/10.1007/3-540-47719-5_33).
[The structure](#structure-of-vss) is mentioned later.
All signers must generate Block VSSs and exchange each other. 

**Block secret share**
Block secret share is a share that is produced at 4.2 Signature Issuing Protocol in [the paper](https://doi.org/10.1007/3-540-47719-5_33).
The value is 32bytes data of private key on secp256k1 curve.

**Local signature**
Local Signature is a signature, which is produced in each signer node at 4.2 Signature Issuing Protocol in [the paper](https://doi.org/10.1007/3-540-47719-5_33).
By collecting Local signatures can generate a final signature, which can be verified by Aggregate public key, with calculating Lagrange interpolation.

## Generate Aggregate public key and Node secret share for Tapyrus Signer Network

Here describes how each signer gets Aggregate public key of Tapyrus Signer Network(TSN) and Node secret share. 
TSN produces signatures for blocks of the Tapyrus blockchain. 
The signatures are equal with that signed by a private key, which is aggregated all signer's private key.
So the signatures can be verified with the public key, which is aggregated all signer's public key. 
However, the TNS doesn't use the aggregate private key to produce the signatures. 
The TNS uses the distributed schnorr signature scheme from [Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold Scheme for Implicit Certificates](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/provably_secure_distributed_schnorr_signatures_and_a_threshold_scheme.pdf).
In this scheme, each signer has its secret share, which is called Node secret share.
The TNS can produce signatures using the Node secret shares whose count equals threshold.

The following steps can be summarized like this: 
* Generate your key pair. 
* Generate and distribute Node VSSs for all each signer.
* By the distribution, you would collect Node VSSs for you from each other signer and yourself.
* Generate Aggregate public key and Node secret share from the collected Node VSSs.

### Step 1. Generate key pair

Each signer generates a node key pair using `tapyrus-setup createkey` independently.

```
tapyrus-setup createkey

output <private_key> <public_key>
```

This generates the private/public key pair based on secp256k1 elliptic curve, where:

- `private_key` is a private key with an extended WIF format[^3].
- `public_key` is a public key corresponding to `private_key` with a hex format string.

[^3]: [BIP-178: Version Extended WIF](https://github.com/bitcoin/bips/blob/master/bip-0178.mediawiki)

Each signer shares their own public key `public_key` to other signers.
And then, they sort received public keys.

In the following steps, Signers are supposed to be sorted by public keys and indexed as Signer[i] (i = 1, 2, 3, ..., n)

### Step 2. Generate node verifiable secret shares.

Signer[i] generates Node VSS with `tapyrus-setup createnodevss`.

```
tapyrus-setup createnodevss --public-key=<public_key[1]> --public-key=<public_key[2]> ... --public-key=<public_key[n]> --private-key=<private_key[i]> --networkid=<networkid> --block-height=<block_height> --threshold=<t>

output:
    <public_key[1]>: <node_vss[i, 1]>,
    <public_key[2]>: <node_vss[i, 2]>,
    ...
    <public_key[n]>: <node_vss[i, n]]>,
```

where:

- `public_key[]` is an array of public keys generated by Signer[j] in Step 1.
- `private_key[i]` is a private key of Signer[i] generated in Step 1.
- `networkid` is Network ID we choose. We use it as a nonce of encryption.
- `block_height` is a 64-bits integer to be applied to this federation. In the initial setup, this should be 0. This option is optional, and the default is 0.
- `t` is the minimum number of signers required to sign block.

And then, Signer[i] send the generated `node_vss[i, j]` (j = 1, 2, ..., n; i != j) to the Signer[j].

The structure of `node_vss[i, j]` is mentioned later in [Structure of VSS](#structure-of-vss).

`node_vss[i, j]` also is encrypted using symmetric key encryption scheme ChaCha20-Poly1305 [^4] and encoding with Base58.
So in generally, one who doesn't know `private_key[i]` can not know the secret value `secret[j]` even if they get `node_vss[i, j]`.
But from a security point of view, Signer[i] should send the value to others using a secure communication channel with PFS.

For more information about encrypting and encoding `node_vss[i, j]`. See Appendix A.

:heavy_exclamation_mark:Caution: 
> The VSS encryption is not implemented at 0.4.0 release. It is going to be implemented in a future release.

[^4]: [ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)

### Step 3. Generate an aggregated public key

Signer[i] receives secret value `node_vss[j, i]` (j = 1, 2, ..., n) from other Signer[j].
After receiving from all signers, Signer[i] aggregate public keys and compute their own secret `node_secret_share[i]`

```
tapyrus-setup aggregate --vss=<node_vss[1, i]> --vss=<node_vss[2, i]> ... --vss=<node_vss[n, i]> --private-key=<private_key[i]>

output: <aggregated_public_key> <node_secret_share[i]>
```

- `node_vss[j, i]`(j = 1, 2, ..., n: i != j) are secret values produced in Step 2 and sent from other Signer[j].
- `node_vss[i, i]` is produced by Signer[i] themselves in Step 2.
- `private_key[i]` is the private key of Signer[i], generated in Step 1.
- `aggregated_public_key` is an aggregated public key.
- `node_secret_share[i]` is the secret key share of Signer[i] with a hex format.

Note that `node_secret_share[i]` is not encrypted because it is not intended to send to any other signers. It should be kept secret from others.


## Generate genesis block proof

Here describe steps for generating genesis block proof. 
It assumes that you already have a genesis block hex string without proof in the header.
If you don't have yet, get it following [Create new genesis block using tapyrus-genesis-utility](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/getting_started.md#how-to-create-a-genesis-block) first.  

The following steps can be summarized like this: 
* Generate and distribute Block VSSs for all each signer.
* By the distribution, you would collect Block VSSs for you from each other signer and yourself.
* Generate Local Signature by the collected Block VSSs and Node secret share.
* Share the Local Signature with all other signers.
* Compute final signature for the block from all collected Local Signatures.

### Step 1. Generate Block VSSs.

As in Step 3, Signer[i] creates Block VSS.

```

tapyrus-setup createblockvss --public-key=<public_key[1]> --public-key=<public_key[2]> ... --public-key=<public_key[n]> --private-key=<private_key[i]> --threshold=<t>

output: {
    <public_key[1]>: <block_vss[i, 1]>,
    <public_key[2]>: <block_vss[i, 2]>,
    ...
    <public_key[n]>: <block_vss[i, n]>,
}

```

where:

- `public_key[]` is an array of public keys generated by Signer[j].
- `private_key[i]` is a private key of Signer[i] generated.
- `t` is the minimum number of signers required to sign block.

Signer[i] does not have to specify a nonce used in the encryption. A nonce is optional in this step.

The structure of `block_vss[i, j]` is mentioned later in [Structure of VSS](#structure-of-vss).

`block_vss[i, j]` is encrypted in the same way as Node VSS.

:heavy_exclamation_mark:Caution: 
> The VSS encryption is not implemented at 0.4.0 release. It is going to be implemented in a future release.

Signer[i] sends the generated values `block_vss[i, j]` to other signers.

### Step 2. Sign the genesis block locally.

Signer[i] secretly receives `block_vss[j, i]` generated by other signers. Then Signer[i] generates Local signature using `tapyrus-setup sign`.

```
tapyrus-setup sign --block-vss=<block_vss[1, i]> --block-vss=<block_vss[2, i]> ... --block-vss=<block_vss[n, i]> --aggregated-public-key=<aggregated_public_key> --nodesecret=<node_secret_share[i]> --private-key=<private_key[i]> --block=<block>

output: <local_sig[i]>
```

- `block_vss[j, i]` (j = 1, 2, ..., n) are Block VSSs generated by Step 1.
- `private_key[i]` is the private key of Signer[i].
- `aggregated_public_key` is an aggregated public key.
- `node_secret_share[i]` is the secret key share of Signer[i].
- `block` is the genesis block without block proof.
- `local_sig[i]` is the "local signature" constains γi in the paper [^4]. signer[i] may reveal `local_sig[i]`.

`local_sig[i]` is encoded hex string of ( r | s | `public_key`).
   - r - the unsigned big-endian 256-bit encoding of the Schnorr signature's r integer.
   - s - the unsigned big-endian 256-bit encoding of the Schnorr signature's s integer.
   - `public_key` is the public key of Signer[i].

Then each signer broadcasts their Local signature.

### Step 3. Compute the signature of the genesis block.

After collecting Local signature, we can compute the signature of the genesis block using `tapyrus-setup computesig`

```
tapyrus-setup computesig --sig=<local_sig[1]> --sig=<local_sig[2]> ... --sig=<local_sig[n]> --private-key=<private_key[i]> --block=<block> --block-vss=<block_vss[1, i]> --block-vss=<block_vss[2, i]> ... --block-vss=<block_vss[n, i]> --node-vss=<node_vss[1, i]> --node-vss=<node_vss[2, i]> ... --node-vss=<node_vss[n, i]>


output: <block_with_signature>
```

- `local_sig[i]` is the local signatures broadcasted by signers.
- `block` is the genesis block without block proof.
- `private_key[i]` is the private key of Signer[i].
- `block_vss[j, i]` (j = 1, 2, ..., n) are Block VSSs.
- `node_vss[j, i]` (j = 1, 2, ..., n) are Node VSSs.
- `block_with_signature` is the whole genesis block data with block proof as hex string format.

To make block proof, t Local signatures are required.
Local signatures generated by signers are public values, so signers can reveal them as plaintext without any encryption.

### Step 4. genesis.`networkid`

Create a file named 'genesis.`networkid`' and fill it with `block_with_signature`.

## Next Step

Now we are ready to start Tapyrus Core and Tapyrus Signer Network.

To start Tapyrus Core Network, see [Start Tapyrus-core nodes](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/getting_started.md#5-start-tapyrus-core-nodes).

To start Tapyrus Signer Network, go to [How To configure Tapyrus Signer Network](./configuration.md). The secret values or keys referred to in this document will be required to start Tapyrus Signer Network.

- `private_key[i]` and `public_key[i]`
- `aggregated_public_key` and `node_secret_share[i]`

In the above list, `private_key` and `node_secret_share` must be treated as secret.

## Appendix A: Encoding and Encrypting the VSS

:heavy_exclamation_mark:Caution: 
> The VSS encryption is not implemented at 0.4.0 release. It is going to be implemented in a future release.

In this section, we describe the protocol to encode/encrypt the VSS.
`node_vss[i, j]` and `block_vss[i, j]` have same structure.

Below in this section, notation `vss` means `node_vss[i, j]` or `block_vss[i, j]`.

### Structure of VSS

VSS has two kinds of VSS, named "positive" and "negative". 
Only a "positive" VSS is used to generate aggregated value. 
For more information, see [^5].

Node VSS and Block VSS have seven fields:

| name                 | size      | explanation                                                                                      |
| -------------------- | --------- | ------------------------------------------------------------------------------------------------- |
| sender_public_key    | 33        | indicates the signer who sends the VSS                                                            |
| receiver_public_key  | 33        | indicates the signer to be received the VSS                                                       |
| positive commitments | 64 \* len | commitments for secret value for r . an array of the points on the elliptic curve secp256k1.      |
| positive secret      | 32        | secret value for r to perform secret sharing scheme                                               |
| negative commitments | 64 \* len | commitments for secret value for (n - r). an array of the points on the elliptic curve secp256k1. |
| negative secret      | 32        | secret value for (n - r) to perform secret sharing scheme                                         |

Both commitments consist of 32-bits x-coordinate and 32-bits y-coordinate.

[^5]: In the schnorr signature schema used in Tapyrus Core, we use the random value "r" and the ephemeral point "R" on the elliptic curve, where R = rG (G is the generator of the curve). In Tapyrus signature scheme, we should choose R so that jacobi(y(R)) = 1 (if not, use (n - r) instead of r and generate R so that R = (n - r)G, where n is the order of the curve). So in this step, we should generate both "positive" secret and commitments that corresponds to r, and "negative" ones that correspond to (n - r). For more information, see [Tapyrus Schnorr Signature Specification](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/schnorr_signature.md)

### Encryption of Node VSS

Node VSS is processed in the rule listed below:

1. Compute p = ECDH(`private_key`, `receiver_public_key`). where ECDH is a Elliptic-Curve Diffie-Hellman function. p represents a point on the secp256k1 and has 33-byte length.
2. Compute k = h(p). where h is SHA256 hash function. k is used as a 32-bytes symmetric key of ChaCha20-Poly1305.
3. Concat all fields except `sender_public_key`.
   payload = `receiver_public_key` || `positive commitments` || `positive secret` || `negative commitments` || `negative secret`
4. Let n be 64 bits of leading zeros followed by a 32-bit nonce, where:
   nonce = h(`public_key[1]` || `public_key[2]` || ... || `public_key[n]` || `networkid` || `block_height` || `threshold`)
5. Encrypt payload with ChaCha20-Poly1305 encrpytion function.
   enc_payload = chacha20_poly1305_encrypt(k, n, ad = '', payload)
6. Encode `sender_public_key` || enc_payload using Base58.

### Encryption of Block VSS

Block VSS is processed in the rule listed below.
It is the same as the encryption of Node VSS except nonce used by chacha20_poly1305_encrypt function.

1. Compute k = ECDH(`private_key`, `receiver_public_key`).
2. Compute sk = h(k). where h is SHA256 hash function.
3. Concat all fields except `sender_public_key`.
   payload = `receiver_public_key` || `positive commitments` || `positive secret` || `negative commitments` || `negative secret`
4. Let n be a 96-bit null-nonce (0x000000000000000000000000).
5. Encrypt payload with ChaCha20-Poly1305 encrpytion function.
   enc_payload = chacha20_poly1305_encrypt(k, n, ad = '', payload)
6. Encode `sender_public_key` || enc_payload using Base58.

## Appendix B: Example Scenario

// TODO: Write usage of tapyrus-vss.

## Appendix C: Security Consideration

:heavy_exclamation_mark:Caution: 
> The VSS encryption is not implemented at 0.4.0 release. It is going to be implemented in a future release.

### Nonce used by Encrypting with ChaCha20-Poly1305

As described in Appendix A, we use ChaCha20-Poly1305 encryption to generate VSS.
`networkid` is used as a nonce in encrypting Node VSS.
Note that according to the security requirement of ChaCha20, so we can not reuse the same Network ID with the same node's keypair.
In generating Block VSS, fixed null-nonce can be used because keypair is ephemeral.

### Communicating with a protocol with PFS

We suppose that signers can establish a secure connection as described in the section [Overview](#Overview)
It is required to use a communication method having the property of PFS to minimize leaked information even if the encryption algorithm used in this version is broken in the future.
Otherwise, the private key and the node secret may leak from the past communication contents.