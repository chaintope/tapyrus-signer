use crate::blockdata::Block;
use crate::errors::Error;
use crate::rpc::{GetBlockchainInfoResult, TapyrusApi};
use bitcoin::Address;
use std::cell::RefCell;
use std::collections::VecDeque;

/// Mock for Rpc
///
/// ## Example
///
/// ```
/// use tapyrus_signer::tests::helper::rpc::MockRpc;
/// use tapyrus_signer::errors::Error;
///
/// // create instance.
/// let mut rpc = MockRpc::new();
///
/// // set stubs
/// rpc.should_call_testproposedblock(Ok(true));
///
/// // error responce stub can be set.
/// let err = Error::JsonRpc(jsonrpc::error::Error::Rpc(jsonrpc::error::RpcError {
///     code: -25,
///     message: "proposal was not based on our best chain".to_string(),
///     data: None,
/// }));
/// rpc.should_call_testproposedblock(Err(err));
///
/// // use rpc here ...
///
/// // check are there any remaining stub
/// rpc.assert();
/// ```
#[derive(Debug)]
pub struct MockRpc {
    getnewblock_results: RefCell<VecDeque<Block>>,
    getblockchaininfo_results: RefCell<VecDeque<GetBlockchainInfoResult>>,
    testproposedblock_results: RefCell<VecDeque<Result<bool, Error>>>,
    submitblock_results: RefCell<VecDeque<Result<(), Error>>>,
}

impl MockRpc {
    pub fn new() -> Self {
        MockRpc {
            getnewblock_results: RefCell::new(VecDeque::new()),
            getblockchaininfo_results: RefCell::new(VecDeque::new()),
            testproposedblock_results: RefCell::new(VecDeque::new()),
            submitblock_results: RefCell::new(VecDeque::new()),
        }
    }

    pub fn assert(&self) {
        assert!(
            self.getnewblock_results.borrow().is_empty(),
            "getnewblock RPC should be called once or more, but not."
        );
        assert!(
            self.getblockchaininfo_results.borrow().is_empty(),
            "getblockchaininfo RPC should be called once or more, but not."
        );
        assert!(
            self.testproposedblock_results.borrow().is_empty(),
            "testproposedblock RPC should be called once or more, but not."
        );
        assert!(
            self.submitblock_results.borrow().is_empty(),
            "submitblock RPC should be called once or more, but not."
        );
    }

    pub fn should_call_getnewblock(&mut self, result: Result<Block, Error>) {
        let mut list = self.getnewblock_results.borrow_mut();
        match result {
            Ok(r) => list.push_front(r),
            Err(_) => unimplemented!("MockRpc not support testing Error result yet."),
        }
    }

    pub fn should_call_testproposedblock(&mut self, result: Result<bool, Error>) {
        let mut list = self.testproposedblock_results.borrow_mut();
        list.push_front(result);
    }

    pub fn should_call_getblockchaininfo(
        &mut self,
        result: Result<GetBlockchainInfoResult, Error>,
    ) {
        let mut list = self.getblockchaininfo_results.borrow_mut();
        match result {
            Ok(r) => list.push_front(r),
            Err(_) => unimplemented!("MockRpc not support testing Error result yet."),
        }
    }

    pub fn should_call_submitblock(&mut self, result: Result<(), Error>) {
        let mut list = self.submitblock_results.borrow_mut();
        list.push_front(result);
    }

    pub fn should_call_testproposedblock_and_returns_invalid_block_error(&mut self) {
        let err = Error::JsonRpc(jsonrpc::error::Error::Rpc(jsonrpc::error::RpcError {
            code: -25,
            message: "proposal was not based on our best chain".to_string(),
            data: None,
        }));
        self.should_call_testproposedblock(Err(err));
    }
}

impl TapyrusApi for MockRpc {
    fn getnewblock(&self, address: &Address) -> Result<Block, Error> {
        let mut list = self.getnewblock_results.borrow_mut();
        let result = list.pop_back().expect(&format!(
            "Unexpected RPC call method=getnewblock, args(address={:?})",
            address
        ));
        Ok(result)
    }

    fn testproposedblock(&self, block: &Block) -> Result<bool, Error> {
        let mut list = self.testproposedblock_results.borrow_mut();
        list.pop_back().expect(&format!(
            "Unexpected RPC call method=testproposedblock, args(block={:?})",
            block
        ))
    }

    fn submitblock(&self, block: &Block) -> Result<(), Error> {
        let mut list = self.submitblock_results.borrow_mut();
        list.pop_back().expect(&format!(
            "Unexpected RPC call method=submitblock, args(block={:?}",
            block
        ))
    }

    fn getblockchaininfo(&self) -> Result<GetBlockchainInfoResult, Error> {
        let mut list = self.getblockchaininfo_results.borrow_mut();
        let result = list
            .pop_back()
            .expect("Unexpected RPC call method=getblockchaininfo");
        Ok(result)
    }
}
