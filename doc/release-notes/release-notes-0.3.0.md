Tapyrus Signer version 0.3.0 is now available for download at: 
  https://github.com/chaintope/tapyrus-signer/release/tag/v0.3.0/
    
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
* Added checking connection to TapyrusCore RPC endpoint when the node is started. If the Core's in Initial Block 
Download(IBD), signer node is going to wait to finish the IBD. If you don't want to wait, you can use 
`--skip-waiting-ibd` option. 
