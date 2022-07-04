# Minimum Signer network example

This is a sample of docker-compose configuring a minimal Signer network with three signers(alice, bob, carol).

## Setup

First, follow [this](/doc/setup.md#generate-aggregate-public-key-and-node-secret-share-for-tapyrus-signer-network)
setup guide to generate an aggregate public key and a secret share for the node in order to set up the three signers.

Copy [signers/federations.toml](signers/federations.toml) and [tapyrus-signer.toml](signers/tapyrus-signer.toml)
to the directories `alice`, `bob` and `carol` directly under `signers` dir.
Then, set the aggregate public key, node vss, and other data in the configuration file with the data you just generated.

Finally, generate the genesis block and place the genesis block file (`genesis.<network id>`) directly under the [tapyrus directory](tapyrus). 
Then, place following `tapyrus.conf` with that network id in the same directory.

    networkid=<network id>
    txindex=1
    server=1
    rest=1
    rpcuser=user
    rpcpassword=pass
    rpcbind=0.0.0.0
    rpcallowip=0.0.0.0/0

When ready, simply run docker-compose:

    $ docker-compose up -d

This will start the block generation with 2/3 threshold. 
tapyrus core blockchain data will be stored in the `tapyrus/prod-<network id>` directory.

