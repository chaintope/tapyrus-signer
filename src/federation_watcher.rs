// Copyright (c) 2019 Chaintope Inc.

//! Watches `federations.toml` for changes on disk and, on a valid edit, delivers the freshly
//! parsed and validated `Federations` to the running signer so it can pick up a newly-appended
//! federation/xfield change without a daemon restart. The block-height gating in
//! `Federation::match_xfield_with_federation` still decides *when* an entry takes effect; this
//! only decides *when the daemon notices a new entry exists*.

use crate::federation::Federations;
use notify::RecursiveMode;
use notify_debouncer_mini::{new_debouncer, DebounceEventResult};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;
use tapyrus::PublicKey;

/// Debounce window for filesystem events. An editor or `mv` (atomic rename) can emit several
/// events for what is conceptually a single update; this coalesces them.
const DEBOUNCE: Duration = Duration::from_millis(300);

/// Spawn a background thread that watches `path`'s parent directory and, whenever `path` itself
/// is created, written, or renamed into place, re-reads and re-validates it via
/// `Federations::from_pubkey_and_toml` (the same validated load path used at startup). A
/// successfully parsed `Federations` is sent on the returned channel; a malformed edit is logged
/// and otherwise ignored, so a bad edit never crashes an already-running signer.
///
/// This call blocks until the underlying OS watch is actually registered (and an initial reload
/// of `path` has been attempted), so there is no gap between `spawn` returning and the watch
/// being live - an edit made immediately after this call returns is never missed.
pub fn spawn(path: PathBuf, pubkey: PublicKey) -> Receiver<Federations> {
    let (federations_tx, federations_rx) = channel();
    let (ready_tx, ready_rx) = channel::<()>();

    std::thread::spawn(move || {
        let watch_dir = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let file_name = match path.file_name() {
            Some(name) => name.to_owned(),
            None => {
                log::error!(
                    "federation_watcher: {:?} has no file name, live reload disabled",
                    path
                );
                return;
            }
        };

        let (fs_tx, fs_rx) = channel::<DebounceEventResult>();
        // The debouncer coalesces raw filesystem events per-path over `DEBOUNCE` and must be
        // kept alive for as long as we want to keep watching (dropping it stops the watch), so
        // it lives as a local binding for the rest of this thread.
        let mut debouncer = match new_debouncer(DEBOUNCE, fs_tx) {
            Ok(d) => d,
            Err(e) => {
                log::error!("federation_watcher: failed to create watcher: {:?}", e);
                return;
            }
        };
        if let Err(e) = debouncer
            .watcher()
            .watch(&watch_dir, RecursiveMode::NonRecursive)
        {
            log::error!(
                "federation_watcher: failed to watch {:?}: {:?}",
                watch_dir,
                e
            );
            return;
        }

        log::info!(
            "federation_watcher: watching {:?} for changes to {:?}",
            watch_dir,
            file_name
        );

        // Close the gap between the initial load in `main` and the watch becoming live: pick up
        // whatever is on disk right now before waiting for the first filesystem event.
        reload(&path, &pubkey, &federations_tx);
        let _ = ready_tx.send(());

        loop {
            match fs_rx.recv() {
                Ok(Ok(events)) => {
                    let touched_our_file = events
                        .iter()
                        .any(|e| e.path.file_name() == Some(file_name.as_os_str()));
                    if touched_our_file && !reload(&path, &pubkey, &federations_tx) {
                        log::warn!(
                            "federation_watcher: signer node is no longer listening, stopping"
                        );
                        return;
                    }
                }
                Ok(Err(e)) => {
                    log::error!("federation_watcher: watch error: {:?}", e);
                }
                Err(_) => {
                    // The debouncer's sender was dropped, which only happens if `debouncer`
                    // itself were dropped - it isn't, since it lives in this same scope.
                    return;
                }
            }
        }
    });

    // Block until the watch is registered (and the initial reload attempted) so callers never
    // race an edit against the watcher's own setup.
    let _ = ready_rx.recv();
    federations_rx
}

/// Re-reads and re-validates `path`, sending a successful result on `federations_tx`.
/// Returns `false` only when the receiving end has gone away (the signer node has shut down),
/// signalling the caller to stop watching; a malformed file is logged and otherwise ignored,
/// still returning `true` so the watcher keeps running.
fn reload(path: &PathBuf, pubkey: &PublicKey, federations_tx: &Sender<Federations>) -> bool {
    let toml = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            log::error!(
                "federation_watcher: failed to read {:?}, keeping last-known-good federations: {:?}",
                path,
                e
            );
            return true;
        }
    };

    match Federations::from_pubkey_and_toml(pubkey, &toml) {
        Ok(federations) => {
            log::info!(
                "federation_watcher: reloaded {:?}, {} federation(s) now known",
                path,
                federations.len()
            );
            federations_tx.send(federations).is_ok()
        }
        Err(e) => {
            log::error!(
                "federation_watcher: {:?} is invalid, keeping last-known-good federations: {:?}",
                path,
                e
            );
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::time::Duration;

    const PUBKEY: &str = "021c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da";
    const GENESIS_TOML: &str = r#"
        [[federation]]
        block-height = 0
        aggregated-public-key = "02459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806"
        "#;
    const GENESIS_PLUS_CHANGE_TOML: &str = r#"
        [[federation]]
        block-height = 0
        aggregated-public-key = "02459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806"
        [[federation]]
        block-height = 40
        aggregated-public-key = "0376c3265e7d81839c1b2312b95697d47cc5b3ab3369a92a5af52ef1c945792f50"
        signature = "90c90936d44e75bf25f8a6d1c21020a8dc7ee7f4d62a3d7ae278d9ff6a74901f687eee4236a64805414a43c344d12882061518be61014e76027cf6b8fd845aa0"
        "#;
    const MALFORMED_TOML: &str = "this is not valid toml [[[";
    // Same second entry as GENESIS_PLUS_CHANGE_TOML, but the last byte of the signature is
    // tampered with so it fails cryptographic verification rather than hex-decoding.
    const INVALID_SIGNATURE_TOML: &str = r#"
        [[federation]]
        block-height = 0
        aggregated-public-key = "02459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806"
        [[federation]]
        block-height = 40
        aggregated-public-key = "0376c3265e7d81839c1b2312b95697d47cc5b3ab3369a92a5af52ef1c945792f50"
        signature = "90c90936d44e75bf25f8a6d1c21020a8dc7ee7f4d62a3d7ae278d9ff6a74901f687eee4236a64805414a43c344d12882061518be61014e76027cf6b8fd845aa1"
        "#;
    // Two entries claiming the same block-height, rejected by `Federations::validate()`.
    const DUPLICATE_HEIGHT_TOML: &str = r#"
        [[federation]]
        block-height = 0
        aggregated-public-key = "02459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806"
        [[federation]]
        block-height = 0
        max-block-size = 400000
        "#;
    // Neither an aggregated pubkey nor a max block size: rejected by `Federation::validate()`.
    const MISSING_XFIELD_TOML: &str = r#"
        [[federation]]
        block-height = 0
        "#;
    // An explicitly empty federation list, rejected by `Federations::validate()`.
    const EMPTY_TOML: &str = "federation = []";
    // No entry at block-height 0: without a floor entry, a later get_by_block_height lookup for
    // any height below 100 would have nothing to return. Rejected by `Federations::validate()`.
    const NO_GENESIS_FLOOR_TOML: &str = r#"
        [[federation]]
        block-height = 100
        aggregated-public-key = "02459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806"
        "#;

    /// Creates a fresh scratch directory under the OS temp dir, unique per test invocation.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tapyrus_signer_federation_watcher_test_{}_{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Writes `contents` to `path` via write-to-temp-then-rename, so the watcher only ever
    /// observes a complete file, matching the atomic-write guidance in `doc/federation.md`.
    fn write_atomically(path: &PathBuf, contents: &str) {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, contents).unwrap();
        std::fs::rename(&tmp, path).unwrap();
    }

    /// `spawn` always attempts an eager reload of whatever is on disk before returning (closing
    /// the gap between the initial load in `main` and the watch becoming live). Every test below
    /// must consume that first message before exercising the edit it actually cares about.
    fn recv_eager_reload(rx: &Receiver<Federations>) -> Federations {
        rx.recv_timeout(Duration::from_secs(2))
            .expect("expected the eager reload spawn() performs before returning")
    }

    #[test]
    fn test_reload_on_valid_edit() {
        let dir = scratch_dir("valid_edit");
        let path = dir.join("federations.toml");
        write_atomically(&path, GENESIS_TOML);

        let pubkey = PublicKey::from_str(PUBKEY).unwrap();
        let rx = spawn(path.clone(), pubkey);
        assert_eq!(recv_eager_reload(&rx).len(), 1);

        write_atomically(&path, GENESIS_PLUS_CHANGE_TOML);

        let federations = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("expected a reload after a valid edit");
        assert_eq!(federations.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Starts a watcher over a fresh `federations.toml` (seeded with `GENESIS_TOML`), then
    /// writes `invalid_toml` and asserts no reload is ever delivered for it: the watcher must
    /// log and keep running rather than send anything the signer would apply.
    fn assert_edit_ignored(name: &str, invalid_toml: &str) {
        let dir = scratch_dir(name);
        let path = dir.join("federations.toml");
        write_atomically(&path, GENESIS_TOML);

        let pubkey = PublicKey::from_str(PUBKEY).unwrap();
        let rx = spawn(path.clone(), pubkey);
        recv_eager_reload(&rx);

        write_atomically(&path, invalid_toml);

        match rx.recv_timeout(Duration::from_secs(2)) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            other => panic!(
                "expected no reload for invalid toml ({}), got {:?}",
                name,
                other.map(|f| f.len())
            ),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_malformed_toml_is_ignored() {
        assert_edit_ignored("malformed", MALFORMED_TOML);
    }

    #[test]
    fn test_invalid_signature_is_ignored() {
        assert_edit_ignored("invalid_signature", INVALID_SIGNATURE_TOML);
    }

    #[test]
    fn test_duplicate_block_height_is_ignored() {
        assert_edit_ignored("duplicate_height", DUPLICATE_HEIGHT_TOML);
    }

    #[test]
    fn test_missing_xfield_is_ignored() {
        assert_edit_ignored("missing_xfield", MISSING_XFIELD_TOML);
    }

    #[test]
    fn test_empty_federation_list_is_ignored() {
        assert_edit_ignored("empty_list", EMPTY_TOML);
    }

    #[test]
    fn test_missing_genesis_floor_is_ignored() {
        assert_edit_ignored("no_genesis_floor", NO_GENESIS_FLOOR_TOML);
    }

    /// A bad edit must not wedge the watcher: a later, valid edit should still be picked up.
    #[test]
    fn test_recovers_after_invalid_edit_then_valid_edit() {
        let dir = scratch_dir("recovery");
        let path = dir.join("federations.toml");
        write_atomically(&path, GENESIS_TOML);

        let pubkey = PublicKey::from_str(PUBKEY).unwrap();
        let rx = spawn(path.clone(), pubkey);
        recv_eager_reload(&rx);

        write_atomically(&path, MALFORMED_TOML);
        match rx.recv_timeout(Duration::from_secs(2)) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            other => panic!(
                "expected no reload for the malformed edit, got {:?}",
                other.map(|f| f.len())
            ),
        }

        write_atomically(&path, GENESIS_PLUS_CHANGE_TOML);
        let federations = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("watcher should still be alive and pick up a later valid edit");
        assert_eq!(federations.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
