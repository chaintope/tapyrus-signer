Tapyrus Signer version 0.4.0 is now available for download at: 
  https://github.com/chaintope/tapyrus-signer/releases/tag/v0.4.0/
    
Please report bugs using the issue tracker at github:
  https://github.com/chaintope/tapyrus-signer/issues
  
Project source code is hosted at github; you can get
source-only tarballs/zipballs directly from there:
  https://github.com/chaintope/tapyrus-signer/tarball/v0.4.0

0.4.0 change log
-------------------

*Trustless setup*

* New command line tool `tapyrus-setup` is available.

* The `nodevss` message is removed. Key generation protocol is treated in out of Tapyrus Signer Network using tapyrus-setup.

* See [setup](https://github.com/chaintope/tapyrus-signer/tree/v0.4.0/doc/setup.md) for more detail.

*Federation management* 

* Make it possible to manage the signing member through configuring federations.toml.

* Remove config parameters `publickeys`, `privatekey`, `threshold` from signer.toml. Write federation parameters in federations.toml instead.

* See [configuration](https://github.com/chaintope/tapyrus-signer/tree/v0.4.0/doc/configuration.md) for more detail.

*New message*

* Add `blockparticipants` to share signers list who participate the signing round.

* See https://github.com/chaintope/tapyrus-signer/issues/29#issuecomment-591860519.

*New block header field*

* Replace the block header field 'appPubkey' to the multipurpose field 'xfield'.

* At v0.4.0, we support None and AggregatePublicKey type only.

* See [Block Structure Expansion for Signed-Blocks](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/signedblocks.md#block-structure-expansion-for-signed-blocks) for more detail.

*Support Snappy*

* Add feature to support Snappy package manager.

*Others*

* Includes some fixes and improvement of codes.


