Release Process
===============

See also [Tapyrus Core Release Process](https://github.com/chaintope/tapyrus-core/blob/master/doc/release-process.md). In general, Tapyrus Signer and Tapyrus Core will be released at the same 
time.

Before every minor and major release:

* Update version in `Cargo.toml`. See also [vertioning rule](https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/versioning_rule.md).
* Write release notes (see below)
* Update Testnet environment. Tapyrus Testnet environment documents are [here](https://drive.google.com/drive/folders/1-J6GE77dH2u5giKoNsuQr24v02bQJjZp) (This is internal document in Chaintope Inc.)
     * We should bland new testnet for new version if the release doesn't have compatibility and keep old testnet for a while.

### Tapyrus maintainers/release engineers, suggestion for writing release notes

Write release notes. git shortlog helps a lot, for example:

    git shortlog --no-merges v(current version, e.g. 0.2.0)..v(new version, e.g. 0.3.0)

Generate list of authors:

    git log --format='- %aN' v(current version, e.g. 0.2.0)..v(new version, e.g. 0.3.1) | sort -fiu

Create release note in `doc/release-notes/tapyrus/`.

Put the summary of the release note on github release like [this](https://github.com/chaintope/tapyrus-signer/releases/tag/v0.3.0)
Release tag is going to create when the github release note published.

## How to build release binary

Tapyrus Signer support osx and linux environment. So we need to prepare binaries for both. Tapyrus Signer pre-built binaries are going to release following archive file on Github release feature like [this](https://github.com/chaintope/tapyrus-signer/releases/tag/v0.3.0) . 

```
tapyrus-signer-v0.3.0-osx64.tar.gz
tapyrus-signer-v0.3.0-x86_64-px-linux-gnu.tar.gz
```

This process assumes on Amazon Linux 2 environment. However it might work on any other Linux environment.

### Build step for Linux

#### Install Rust Compiler

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ source $HOME/.cargo/env
$ rustc --version
rustc 1.39.0 (4560ea788 2019-11-04)
```

#### Install Packages

```$xslt
$ sudo yum install gcc gcc-c++ gpm-devel
```

#### Build Tapyrus Signer

```
$ git clone git@github.com:chaintope/tapyrus-signer.git
$ cd tapyrus-signer
$ cargo build --release
```

#### Create archive

```
$ mkdir -p tapyrus-signer-${VERSION}-x86_64-px-linux-gnu/bin
$ cp target/release/node tapyrus-signer-${VERSION}-x86_64-px-linux-gnu/bin
$ tar zcvf tapyrus-signer-${VERSION}-x86_64-px-linux-gnu.tar.gz tapyrus-signer-${VERSION}-x86_64-px-linux-gnu/
```

### Build step for OSX

#### Install Rust Compiler

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ source $HOME/.cargo/env
$ rustc --version
rustc 1.39.0 (4560ea788 2019-11-04)
```

#### Build Tapyrus Signer

```
$ git clone git@github.com:chaintope/tapyrus-signer.git
$ cd tapyrus-signer
$ cargo build --release
```

#### Create archive

```
$ mkdir -p tapyrus-signer-${VERSION}-x86_64-px-linux-gnu/bin
$ cp target/release/node tapyrus-signer-${VERSION}-x86_64-px-linux-gnu/bin
$ tar zcvf tapyrus-signer-${VERSION}-x86_64-px-linux-gnu.tar.gz tapyrus-signer-${VERSION}-x86_64-px-linux-gnu/
```

