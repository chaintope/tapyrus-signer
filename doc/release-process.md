How to build release binary
==============================

This process assumes on Amazon Linux 2 environment. However it might work on any other Linux environment.

Install Rust Compiler
-----------------------
```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ source $HOME/.cargo/env
$ rustc --version
rustc 1.39.0 (4560ea788 2019-11-04)
```

Install Packages
------------

```$xslt
$ sudo yum install gcc gcc-c++ gpm-devel
```

Build Tapyrus Signer
--------------------
```$xslt
$ git clone git@github.com:chaintope/tapyrus-signer.git
$ cd tapyrus-signer
$ cargo build --release
```

