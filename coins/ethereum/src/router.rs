pub use router::*;
#[rustfmt::skip]
#[allow(clippy::too_many_arguments, non_camel_case_types)]
pub mod router {
  #![allow(clippy::enum_variant_names)]
  #![allow(dead_code)]
  #![allow(clippy::type_complexity)]
  #![allow(unused_imports)]
  #[doc = "Router was auto-generated with ethers-rs Abigen. More information at: https://github.com/gakonst/ethers-rs"]
  use std::sync::Arc;
  use ethers::core::{
    abi::{Abi, Token, Detokenize, InvalidOutputType, Tokenizable},
    types::*,
  };
  use ethers::contract::{
    Contract,
    builders::{ContractCall, Event},
    Lazy,
  };
  use ethers::providers::Middleware;
  # [rustfmt :: skip] const __ABI : & str = "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\",\"outputs\":[]},{\"inputs\":[],\"type\":\"error\",\"name\":\"PublicKeyAlreadySet\",\"outputs\":[]},{\"inputs\":[],\"type\":\"error\",\"name\":\"Unauthorized\",\"outputs\":[]},{\"inputs\":[],\"type\":\"error\",\"name\":\"VerificationError\",\"outputs\":[]},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\",\"components\":[],\"indexed\":false},{\"internalType\":\"uint256\",\"name\":\"success\",\"type\":\"uint256\",\"components\":[],\"indexed\":false}],\"type\":\"event\",\"name\":\"Executed\",\"outputs\":[],\"anonymous\":false},{\"inputs\":[],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"Q\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\",\"components\":[]}]},{\"inputs\":[{\"internalType\":\"struct Router.Transaction[]\",\"name\":\"transactions\",\"type\":\"tuple[]\",\"components\":[{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\",\"components\":[]},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\",\"components\":[]},{\"internalType\":\"uint256\",\"name\":\"gas\",\"type\":\"uint256\",\"components\":[]},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\",\"components\":[]}]},{\"internalType\":\"struct Router.Signature\",\"name\":\"sig\",\"type\":\"tuple\",\"components\":[{\"internalType\":\"bytes32\",\"name\":\"e\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"s\",\"type\":\"bytes32\",\"components\":[]}]}],\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"name\":\"execute\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\",\"components\":[]}]},{\"inputs\":[],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"getNonce\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\",\"components\":[]}]},{\"inputs\":[],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"nonce\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\",\"components\":[]}]},{\"inputs\":[],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\",\"components\":[]}]},{\"inputs\":[],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"publicKey\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"parity\",\"type\":\"uint8\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"px\",\"type\":\"bytes32\",\"components\":[]}]},{\"inputs\":[{\"internalType\":\"struct Router.PublicKey\",\"name\":\"_publicKey\",\"type\":\"tuple\",\"components\":[{\"internalType\":\"uint8\",\"name\":\"parity\",\"type\":\"uint8\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"px\",\"type\":\"bytes32\",\"components\":[]}]}],\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"name\":\"setPublicKey\",\"outputs\":[]},{\"inputs\":[{\"internalType\":\"struct Router.PublicKey\",\"name\":\"_publicKey\",\"type\":\"tuple\",\"components\":[{\"internalType\":\"uint8\",\"name\":\"parity\",\"type\":\"uint8\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"px\",\"type\":\"bytes32\",\"components\":[]}]},{\"internalType\":\"struct Router.Signature\",\"name\":\"sig\",\"type\":\"tuple\",\"components\":[{\"internalType\":\"bytes32\",\"name\":\"e\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"s\",\"type\":\"bytes32\",\"components\":[]}]}],\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"name\":\"updatePublicKey\",\"outputs\":[]},{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"parity\",\"type\":\"uint8\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"px\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"message\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"e\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"s\",\"type\":\"bytes32\",\"components\":[]}],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"verify\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\",\"components\":[]}]}]" ;
  #[doc = r" The parsed JSON-ABI of the contract."]
  pub static ROUTER_ABI: ethers::contract::Lazy<ethers::core::abi::Abi> =
    ethers::contract::Lazy::new(|| {
      ethers::core::utils::__serde_json::from_str(__ABI).expect("invalid abi")
    });
  #[doc = r" Bytecode of the #name contract"]
  pub static ROUTER_BYTECODE: ethers::contract::Lazy<ethers::core::types::Bytes> =
    ethers::contract::Lazy::new(|| {
      "0x608060405234801561001057600080fd5b50600160008190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610e12806100696000396000f3fe608060405234801561001057600080fd5b50600436106100935760003560e01c80638da5cb5b116100665780638da5cb5b1461011f5780639186da4c1461013d578063affed0e01461016d578063d087d2881461018b578063e493ef8c146101a957610093565b80631811024d1461009857806337088665146100c8578063459e93e5146100e457806363ffab3114610100575b600080fd5b6100b260048036038101906100ad91906107f3565b6101c7565b6040516100bf919061086e565b60405180910390f35b6100e260048036038101906100dd9190610912565b6101e4565b005b6100fe60048036038101906100f99190610952565b6102b1565b005b6101086103ac565b60405161011692919061099d565b60405180910390f35b6101276103cb565b6040516101349190610a07565b60405180910390f35b61015760048036038101906101529190610a22565b6103f1565b604051610164919061086e565b60405180910390f35b6101756105d6565b6040516101829190610ab6565b60405180910390f35b6101936105dc565b6040516101a09190610ab6565b60405180910390f35b6101b16105e6565b6040516101be9190610ab6565b60405180910390f35b60006101d161060a565b600190506101dd610659565b9392505050565b600082600001518360200151604051602001610201929190610b28565b604051602081830303815290604052805190602001209050610245600360000160009054906101000a900460ff1660036001015483856000015186602001516103f1565b61027b576040517ffbcb0b3400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b82600360008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160010155905050505050565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610338576040517f82b4290000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6000801b60036001015414610379576040517f3b3cf97000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b8060000151600360000160006101000a81548160ff021916908360ff160217905550806020015160036001018190555050565b60038060000160009054906101000a900460ff16908060010154905082565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000807ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641418061042357610422610b54565b5b8660001c8460001c097ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641416104579190610bb2565b60001b905060007ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641418061048d5761048c610b54565b5b8760001c8660001c097ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641416104c19190610bb2565b60001b90506000801b82036104d557600080fd5b60006001838a8a85604051600081526020016040526040516104fa9493929190610be6565b6020604051602081039080840390855afa15801561051c573d6000803e3d6000fd5b505050602060405103519050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603610597576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161058e90610c88565b60405180910390fd5b808989468a6040516020016105b0959493929190610d11565b604051602081830303815290604052805190602001208614935050505095945050505050565b60025481565b6000600254905090565b7ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414181565b60026000540361064f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161064690610dbc565b60405180910390fd5b6002600081905550565b6001600081905550565b6000604051905090565b600080fd5b600080fd5b600080fd5b600080fd5b600080fd5b60008083601f84011261069c5761069b610677565b5b8235905067ffffffffffffffff8111156106b9576106b861067c565b5b6020830191508360208202830111156106d5576106d4610681565b5b9250929050565b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61072a826106e1565b810181811067ffffffffffffffff82111715610749576107486106f2565b5b80604052505050565b600061075c610663565b90506107688282610721565b919050565b6000819050919050565b6107808161076d565b811461078b57600080fd5b50565b60008135905061079d81610777565b92915050565b6000604082840312156107b9576107b86106dc565b5b6107c36040610752565b905060006107d38482850161078e565b60008301525060206107e78482850161078e565b60208301525092915050565b60008060006060848603121561080c5761080b61066d565b5b600084013567ffffffffffffffff81111561082a57610829610672565b5b61083686828701610686565b93509350506020610849868287016107a3565b9150509250925092565b60008115159050919050565b61086881610853565b82525050565b6000602082019050610883600083018461085f565b92915050565b600060ff82169050919050565b61089f81610889565b81146108aa57600080fd5b50565b6000813590506108bc81610896565b92915050565b6000604082840312156108d8576108d76106dc565b5b6108e26040610752565b905060006108f2848285016108ad565b60008301525060206109068482850161078e565b60208301525092915050565b600080608083850312156109295761092861066d565b5b6000610937858286016108c2565b9250506040610948858286016107a3565b9150509250929050565b6000604082840312156109685761096761066d565b5b6000610976848285016108c2565b91505092915050565b61098881610889565b82525050565b6109978161076d565b82525050565b60006040820190506109b2600083018561097f565b6109bf602083018461098e565b9392505050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006109f1826109c6565b9050919050565b610a01816109e6565b82525050565b6000602082019050610a1c60008301846109f8565b92915050565b600080600080600060a08688031215610a3e57610a3d61066d565b5b6000610a4c888289016108ad565b9550506020610a5d8882890161078e565b9450506040610a6e8882890161078e565b9350506060610a7f8882890161078e565b9250506080610a908882890161078e565b9150509295509295909350565b6000819050919050565b610ab081610a9d565b82525050565b6000602082019050610acb6000830184610aa7565b92915050565b60008160f81b9050919050565b6000610ae982610ad1565b9050919050565b610b01610afc82610889565b610ade565b82525050565b6000819050919050565b610b22610b1d8261076d565b610b07565b82525050565b6000610b348285610af0565b600182019150610b448284610b11565b6020820191508190509392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000610bbd82610a9d565b9150610bc883610a9d565b9250828203905081811115610be057610bdf610b83565b5b92915050565b6000608082019050610bfb600083018761098e565b610c08602083018661097f565b610c15604083018561098e565b610c22606083018461098e565b95945050505050565b600082825260208201905092915050565b7f65637265636f766572206661696c656400000000000000000000000000000000600082015250565b6000610c72601083610c2b565b9150610c7d82610c3c565b602082019050919050565b60006020820190508181036000830152610ca181610c65565b9050919050565b60008160601b9050919050565b6000610cc082610ca8565b9050919050565b6000610cd282610cb5565b9050919050565b610cea610ce5826109e6565b610cc7565b82525050565b6000819050919050565b610d0b610d0682610a9d565b610cf0565b82525050565b6000610d1d8288610cd9565b601482019150610d2d8287610af0565b600182019150610d3d8286610b11565b602082019150610d4d8285610cfa565b602082019150610d5d8284610b11565b6020820191508190509695505050505050565b7f5265656e7472616e637947756172643a207265656e7472616e742063616c6c00600082015250565b6000610da6601f83610c2b565b9150610db182610d70565b602082019050919050565b60006020820190508181036000830152610dd581610d99565b905091905056fea2646970667358221220e80dcb74c5aa89721019ea4e0d35d4c3d375c6b149a72f02ea8cfb1cb0f0258c64736f6c63430008110033" . parse () . expect ("invalid bytecode")
    });
  pub struct Router<M>(ethers::contract::Contract<M>);
  impl<M> Clone for Router<M> {
    fn clone(&self) -> Self {
      Router(self.0.clone())
    }
  }
  impl<M> std::ops::Deref for Router<M> {
    type Target = ethers::contract::Contract<M>;
    fn deref(&self) -> &Self::Target {
      &self.0
    }
  }
  impl<M> std::fmt::Debug for Router<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
      f.debug_tuple(stringify!(Router)).field(&self.address()).finish()
    }
  }
  impl<M: ethers::providers::Middleware> Router<M> {
    #[doc = r" Creates a new contract instance with the specified `ethers`"]
    #[doc = r" client at the given `Address`. The contract derefs to a `ethers::Contract`"]
    #[doc = r" object"]
    pub fn new<T: Into<ethers::core::types::Address>>(
      address: T,
      client: ::std::sync::Arc<M>,
    ) -> Self {
      ethers::contract::Contract::new(address.into(), ROUTER_ABI.clone(), client).into()
    }
    #[doc = r" Constructs the general purpose `Deployer` instance based on the provided constructor arguments and sends it."]
    #[doc = r" Returns a new instance of a deployer that returns an instance of this contract after sending the transaction"]
    #[doc = r""]
    #[doc = r" Notes:"]
    #[doc = r" 1. If there are no constructor arguments, you should pass `()` as the argument."]
    #[doc = r" 1. The default poll duration is 7 seconds."]
    #[doc = r" 1. The default number of confirmations is 1 block."]
    #[doc = r""]
    #[doc = r""]
    #[doc = r" # Example"]
    #[doc = r""]
    #[doc = r" Generate contract bindings with `abigen!` and deploy a new contract instance."]
    #[doc = r""]
    #[doc = r" *Note*: this requires a `bytecode` and `abi` object in the `greeter.json` artifact."]
    #[doc = r""]
    #[doc = r" ```ignore"]
    #[doc = r" # async fn deploy<M: ethers::providers::Middleware>(client: ::std::sync::Arc<M>) {"]
    #[doc = r#"     abigen!(Greeter,"../greeter.json");"#]
    #[doc = r""]
    #[doc = r#"    let greeter_contract = Greeter::deploy(client, "Hello world!".to_string()).unwrap().send().await.unwrap();"#]
    #[doc = r"    let msg = greeter_contract.greet().call().await.unwrap();"]
    #[doc = r" # }"]
    #[doc = r" ```"]
    pub fn deploy<T: ethers::core::abi::Tokenize>(
      client: ::std::sync::Arc<M>,
      constructor_args: T,
    ) -> ::std::result::Result<
      ethers::contract::builders::ContractDeployer<M, Self>,
      ethers::contract::ContractError<M>,
    > {
      let factory = ethers::contract::ContractFactory::new(
        ROUTER_ABI.clone(),
        ROUTER_BYTECODE.clone().into(),
        client,
      );
      let deployer = factory.deploy(constructor_args)?;
      let deployer = ethers::contract::ContractDeployer::new(deployer);
      Ok(deployer)
    }
    #[doc = "Calls the contract's `Q` (0xe493ef8c) function"]
    pub fn q(&self) -> ethers::contract::builders::ContractCall<M, ethers::core::types::U256> {
      self
        .0
        .method_hash([228, 147, 239, 140], ())
        .expect("method not found (this should never happen)")
    }
    #[doc = "Calls the contract's `execute` (0x1811024d) function"]
    pub fn execute(
      &self,
      transactions: ::std::vec::Vec<Transaction>,
      sig: Signature,
    ) -> ethers::contract::builders::ContractCall<M, bool> {
      self
        .0
        .method_hash([24, 17, 2, 77], (transactions, sig))
        .expect("method not found (this should never happen)")
    }
    #[doc = "Calls the contract's `getNonce` (0xd087d288) function"]
    pub fn get_nonce(
      &self,
    ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::U256> {
      self
        .0
        .method_hash([208, 135, 210, 136], ())
        .expect("method not found (this should never happen)")
    }
    #[doc = "Calls the contract's `nonce` (0xaffed0e0) function"]
    pub fn nonce(&self) -> ethers::contract::builders::ContractCall<M, ethers::core::types::U256> {
      self
        .0
        .method_hash([175, 254, 208, 224], ())
        .expect("method not found (this should never happen)")
    }
    #[doc = "Calls the contract's `owner` (0x8da5cb5b) function"]
    pub fn owner(
      &self,
    ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::Address> {
      self
        .0
        .method_hash([141, 165, 203, 91], ())
        .expect("method not found (this should never happen)")
    }
    #[doc = "Calls the contract's `publicKey` (0x63ffab31) function"]
    pub fn public_key(&self) -> ethers::contract::builders::ContractCall<M, (u8, [u8; 32])> {
      self
        .0
        .method_hash([99, 255, 171, 49], ())
        .expect("method not found (this should never happen)")
    }
    #[doc = "Calls the contract's `setPublicKey` (0x459e93e5) function"]
    pub fn set_public_key(
      &self,
      public_key: PublicKey,
    ) -> ethers::contract::builders::ContractCall<M, ()> {
      self
        .0
        .method_hash([69, 158, 147, 229], (public_key,))
        .expect("method not found (this should never happen)")
    }
    #[doc = "Calls the contract's `updatePublicKey` (0x37088665) function"]
    pub fn update_public_key(
      &self,
      public_key: PublicKey,
      sig: Signature,
    ) -> ethers::contract::builders::ContractCall<M, ()> {
      self
        .0
        .method_hash([55, 8, 134, 101], (public_key, sig))
        .expect("method not found (this should never happen)")
    }
    #[doc = "Calls the contract's `verify` (0x9186da4c) function"]
    pub fn verify(
      &self,
      parity: u8,
      px: [u8; 32],
      message: [u8; 32],
      e: [u8; 32],
      s: [u8; 32],
    ) -> ethers::contract::builders::ContractCall<M, bool> {
      self
        .0
        .method_hash([145, 134, 218, 76], (parity, px, message, e, s))
        .expect("method not found (this should never happen)")
    }
    #[doc = "Gets the contract's `Executed` event"]
    pub fn executed_filter(&self) -> ethers::contract::builders::Event<M, ExecutedFilter> {
      self.0.event()
    }
    #[doc = r" Returns an [`Event`](#ethers_contract::builders::Event) builder for all events of this contract"]
    pub fn events(&self) -> ethers::contract::builders::Event<M, ExecutedFilter> {
      self.0.event_with_filter(Default::default())
    }
  }
  impl<M: ethers::providers::Middleware> From<ethers::contract::Contract<M>> for Router<M> {
    fn from(contract: ethers::contract::Contract<M>) -> Self {
      Self(contract)
    }
  }
  #[doc = "Custom Error type `PublicKeyAlreadySet` with signature `PublicKeyAlreadySet()` and selector `[59, 60, 249, 112]`"]
  #[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    ethers :: contract :: EthError,
    ethers :: contract :: EthDisplay,
  )]
  #[etherror(name = "PublicKeyAlreadySet", abi = "PublicKeyAlreadySet()")]
  pub struct PublicKeyAlreadySet;
  #[doc = "Custom Error type `Unauthorized` with signature `Unauthorized()` and selector `[130, 180, 41, 0]`"]
  #[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    ethers :: contract :: EthError,
    ethers :: contract :: EthDisplay,
  )]
  #[etherror(name = "Unauthorized", abi = "Unauthorized()")]
  pub struct Unauthorized;
  #[doc = "Custom Error type `VerificationError` with signature `VerificationError()` and selector `[251, 203, 11, 52]`"]
  #[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    ethers :: contract :: EthError,
    ethers :: contract :: EthDisplay,
  )]
  #[etherror(name = "VerificationError", abi = "VerificationError()")]
  pub struct VerificationError;
  #[derive(Debug, Clone, PartialEq, Eq, ethers :: contract :: EthAbiType)]
  pub enum RouterErrors {
    PublicKeyAlreadySet(PublicKeyAlreadySet),
    Unauthorized(Unauthorized),
    VerificationError(VerificationError),
  }
  impl ethers::core::abi::AbiDecode for RouterErrors {
    fn decode(data: impl AsRef<[u8]>) -> ::std::result::Result<Self, ethers::core::abi::AbiError> {
      if let Ok(decoded) =
        <PublicKeyAlreadySet as ethers::core::abi::AbiDecode>::decode(data.as_ref())
      {
        return Ok(RouterErrors::PublicKeyAlreadySet(decoded));
      }
      if let Ok(decoded) = <Unauthorized as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
        return Ok(RouterErrors::Unauthorized(decoded));
      }
      if let Ok(decoded) =
        <VerificationError as ethers::core::abi::AbiDecode>::decode(data.as_ref())
      {
        return Ok(RouterErrors::VerificationError(decoded));
      }
      Err(ethers::core::abi::Error::InvalidData.into())
    }
  }
  impl ethers::core::abi::AbiEncode for RouterErrors {
    fn encode(self) -> Vec<u8> {
      match self {
        RouterErrors::PublicKeyAlreadySet(element) => element.encode(),
        RouterErrors::Unauthorized(element) => element.encode(),
        RouterErrors::VerificationError(element) => element.encode(),
      }
    }
  }
  impl ::std::fmt::Display for RouterErrors {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
      match self {
        RouterErrors::PublicKeyAlreadySet(element) => element.fmt(f),
        RouterErrors::Unauthorized(element) => element.fmt(f),
        RouterErrors::VerificationError(element) => element.fmt(f),
      }
    }
  }
  impl ::std::convert::From<PublicKeyAlreadySet> for RouterErrors {
    fn from(var: PublicKeyAlreadySet) -> Self {
      RouterErrors::PublicKeyAlreadySet(var)
    }
  }
  impl ::std::convert::From<Unauthorized> for RouterErrors {
    fn from(var: Unauthorized) -> Self {
      RouterErrors::Unauthorized(var)
    }
  }
  impl ::std::convert::From<VerificationError> for RouterErrors {
    fn from(var: VerificationError) -> Self {
      RouterErrors::VerificationError(var)
    }
  }
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthEvent,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethevent(name = "Executed", abi = "Executed(uint256,uint256)")]
  pub struct ExecutedFilter {
    pub nonce: ethers::core::types::U256,
    pub success: ethers::core::types::U256,
  }
  #[doc = "Container type for all input parameters for the `Q` function with signature `Q()` and selector `[228, 147, 239, 140]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "Q", abi = "Q()")]
  pub struct QCall;
  #[doc = "Container type for all input parameters for the `execute` function with signature `execute((address,uint256,uint256,bytes)[],(bytes32,bytes32))` and selector `[24, 17, 2, 77]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "execute", abi = "execute((address,uint256,uint256,bytes)[],(bytes32,bytes32))")]
  pub struct ExecuteCall {
    pub transactions: ::std::vec::Vec<Transaction>,
    pub sig: Signature,
  }
  #[doc = "Container type for all input parameters for the `getNonce` function with signature `getNonce()` and selector `[208, 135, 210, 136]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "getNonce", abi = "getNonce()")]
  pub struct GetNonceCall;
  #[doc = "Container type for all input parameters for the `nonce` function with signature `nonce()` and selector `[175, 254, 208, 224]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "nonce", abi = "nonce()")]
  pub struct NonceCall;
  #[doc = "Container type for all input parameters for the `owner` function with signature `owner()` and selector `[141, 165, 203, 91]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "owner", abi = "owner()")]
  pub struct OwnerCall;
  #[doc = "Container type for all input parameters for the `publicKey` function with signature `publicKey()` and selector `[99, 255, 171, 49]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "publicKey", abi = "publicKey()")]
  pub struct PublicKeyCall;
  #[doc = "Container type for all input parameters for the `setPublicKey` function with signature `setPublicKey((uint8,bytes32))` and selector `[69, 158, 147, 229]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "setPublicKey", abi = "setPublicKey((uint8,bytes32))")]
  pub struct SetPublicKeyCall {
    pub public_key: PublicKey,
  }
  #[doc = "Container type for all input parameters for the `updatePublicKey` function with signature `updatePublicKey((uint8,bytes32),(bytes32,bytes32))` and selector `[55, 8, 134, 101]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "updatePublicKey", abi = "updatePublicKey((uint8,bytes32),(bytes32,bytes32))")]
  pub struct UpdatePublicKeyCall {
    pub public_key: PublicKey,
    pub sig: Signature,
  }
  #[doc = "Container type for all input parameters for the `verify` function with signature `verify(uint8,bytes32,bytes32,bytes32,bytes32)` and selector `[145, 134, 218, 76]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "verify", abi = "verify(uint8,bytes32,bytes32,bytes32,bytes32)")]
  pub struct VerifyCall {
    pub parity: u8,
    pub px: [u8; 32],
    pub message: [u8; 32],
    pub e: [u8; 32],
    pub s: [u8; 32],
  }
  #[derive(Debug, Clone, PartialEq, Eq, ethers :: contract :: EthAbiType)]
  pub enum RouterCalls {
    Q(QCall),
    Execute(ExecuteCall),
    GetNonce(GetNonceCall),
    Nonce(NonceCall),
    Owner(OwnerCall),
    PublicKey(PublicKeyCall),
    SetPublicKey(SetPublicKeyCall),
    UpdatePublicKey(UpdatePublicKeyCall),
    Verify(VerifyCall),
  }
  impl ethers::core::abi::AbiDecode for RouterCalls {
    fn decode(data: impl AsRef<[u8]>) -> ::std::result::Result<Self, ethers::core::abi::AbiError> {
      if let Ok(decoded) = <QCall as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
        return Ok(RouterCalls::Q(decoded));
      }
      if let Ok(decoded) = <ExecuteCall as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
        return Ok(RouterCalls::Execute(decoded));
      }
      if let Ok(decoded) = <GetNonceCall as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
        return Ok(RouterCalls::GetNonce(decoded));
      }
      if let Ok(decoded) = <NonceCall as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
        return Ok(RouterCalls::Nonce(decoded));
      }
      if let Ok(decoded) = <OwnerCall as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
        return Ok(RouterCalls::Owner(decoded));
      }
      if let Ok(decoded) = <PublicKeyCall as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
        return Ok(RouterCalls::PublicKey(decoded));
      }
      if let Ok(decoded) = <SetPublicKeyCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
      {
        return Ok(RouterCalls::SetPublicKey(decoded));
      }
      if let Ok(decoded) =
        <UpdatePublicKeyCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
      {
        return Ok(RouterCalls::UpdatePublicKey(decoded));
      }
      if let Ok(decoded) = <VerifyCall as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
        return Ok(RouterCalls::Verify(decoded));
      }
      Err(ethers::core::abi::Error::InvalidData.into())
    }
  }
  impl ethers::core::abi::AbiEncode for RouterCalls {
    fn encode(self) -> Vec<u8> {
      match self {
        RouterCalls::Q(element) => element.encode(),
        RouterCalls::Execute(element) => element.encode(),
        RouterCalls::GetNonce(element) => element.encode(),
        RouterCalls::Nonce(element) => element.encode(),
        RouterCalls::Owner(element) => element.encode(),
        RouterCalls::PublicKey(element) => element.encode(),
        RouterCalls::SetPublicKey(element) => element.encode(),
        RouterCalls::UpdatePublicKey(element) => element.encode(),
        RouterCalls::Verify(element) => element.encode(),
      }
    }
  }
  impl ::std::fmt::Display for RouterCalls {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
      match self {
        RouterCalls::Q(element) => element.fmt(f),
        RouterCalls::Execute(element) => element.fmt(f),
        RouterCalls::GetNonce(element) => element.fmt(f),
        RouterCalls::Nonce(element) => element.fmt(f),
        RouterCalls::Owner(element) => element.fmt(f),
        RouterCalls::PublicKey(element) => element.fmt(f),
        RouterCalls::SetPublicKey(element) => element.fmt(f),
        RouterCalls::UpdatePublicKey(element) => element.fmt(f),
        RouterCalls::Verify(element) => element.fmt(f),
      }
    }
  }
  impl ::std::convert::From<QCall> for RouterCalls {
    fn from(var: QCall) -> Self {
      RouterCalls::Q(var)
    }
  }
  impl ::std::convert::From<ExecuteCall> for RouterCalls {
    fn from(var: ExecuteCall) -> Self {
      RouterCalls::Execute(var)
    }
  }
  impl ::std::convert::From<GetNonceCall> for RouterCalls {
    fn from(var: GetNonceCall) -> Self {
      RouterCalls::GetNonce(var)
    }
  }
  impl ::std::convert::From<NonceCall> for RouterCalls {
    fn from(var: NonceCall) -> Self {
      RouterCalls::Nonce(var)
    }
  }
  impl ::std::convert::From<OwnerCall> for RouterCalls {
    fn from(var: OwnerCall) -> Self {
      RouterCalls::Owner(var)
    }
  }
  impl ::std::convert::From<PublicKeyCall> for RouterCalls {
    fn from(var: PublicKeyCall) -> Self {
      RouterCalls::PublicKey(var)
    }
  }
  impl ::std::convert::From<SetPublicKeyCall> for RouterCalls {
    fn from(var: SetPublicKeyCall) -> Self {
      RouterCalls::SetPublicKey(var)
    }
  }
  impl ::std::convert::From<UpdatePublicKeyCall> for RouterCalls {
    fn from(var: UpdatePublicKeyCall) -> Self {
      RouterCalls::UpdatePublicKey(var)
    }
  }
  impl ::std::convert::From<VerifyCall> for RouterCalls {
    fn from(var: VerifyCall) -> Self {
      RouterCalls::Verify(var)
    }
  }
  #[doc = "Container type for all return fields from the `Q` function with signature `Q()` and selector `[228, 147, 239, 140]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
    Default,
  )]
  pub struct QReturn(pub ethers::core::types::U256);
  #[doc = "Container type for all return fields from the `execute` function with signature `execute((address,uint256,uint256,bytes)[],(bytes32,bytes32))` and selector `[24, 17, 2, 77]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
    Default,
  )]
  pub struct ExecuteReturn(pub bool);
  #[doc = "Container type for all return fields from the `getNonce` function with signature `getNonce()` and selector `[208, 135, 210, 136]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
    Default,
  )]
  pub struct GetNonceReturn(pub ethers::core::types::U256);
  #[doc = "Container type for all return fields from the `nonce` function with signature `nonce()` and selector `[175, 254, 208, 224]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
    Default,
  )]
  pub struct NonceReturn(pub ethers::core::types::U256);
  #[doc = "Container type for all return fields from the `owner` function with signature `owner()` and selector `[141, 165, 203, 91]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
    Default,
  )]
  pub struct OwnerReturn(pub ethers::core::types::Address);
  #[doc = "Container type for all return fields from the `publicKey` function with signature `publicKey()` and selector `[99, 255, 171, 49]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
    Default,
  )]
  pub struct PublicKeyReturn {
    pub parity: u8,
    pub px: [u8; 32],
  }
  #[doc = "Container type for all return fields from the `verify` function with signature `verify(uint8,bytes32,bytes32,bytes32,bytes32)` and selector `[145, 134, 218, 76]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
    Default,
  )]
  pub struct VerifyReturn(pub bool);
  #[doc = "`PublicKey(uint8,bytes32)`"]
  #[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
  )]
  pub struct PublicKey {
    pub parity: u8,
    pub px: [u8; 32],
  }
  #[doc = "`Signature(bytes32,bytes32)`"]
  #[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
  )]
  pub struct Signature {
    pub e: [u8; 32],
    pub s: [u8; 32],
  }
  #[doc = "`Transaction(address,uint256,uint256,bytes)`"]
  #[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
  )]
  pub struct Transaction {
    pub to: ethers::core::types::Address,
    pub value: ethers::core::types::U256,
    pub gas: ethers::core::types::U256,
    pub data: ethers::core::types::Bytes,
  }
}
