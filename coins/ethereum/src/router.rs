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
  # [rustfmt :: skip] const __ABI : & str = "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\",\"outputs\":[]},{\"inputs\":[],\"type\":\"error\",\"name\":\"PublicKeyAlreadySet\",\"outputs\":[]},{\"inputs\":[],\"type\":\"error\",\"name\":\"Unauthorized\",\"outputs\":[]},{\"inputs\":[],\"type\":\"error\",\"name\":\"VerificationError\",\"outputs\":[]},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\",\"components\":[],\"indexed\":false},{\"internalType\":\"uint256\",\"name\":\"success\",\"type\":\"uint256\",\"components\":[],\"indexed\":false}],\"type\":\"event\",\"name\":\"Executed\",\"outputs\":[],\"anonymous\":false},{\"inputs\":[],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"KEY_PARITY\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\",\"components\":[]}]},{\"inputs\":[],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"Q\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\",\"components\":[]}]},{\"inputs\":[{\"internalType\":\"struct Router.RTransaction[]\",\"name\":\"transactions\",\"type\":\"tuple[]\",\"components\":[{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\",\"components\":[]},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\",\"components\":[]},{\"internalType\":\"uint256\",\"name\":\"gas\",\"type\":\"uint256\",\"components\":[]},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\",\"components\":[]}]},{\"internalType\":\"struct Router.RSignature\",\"name\":\"sig\",\"type\":\"tuple\",\"components\":[{\"internalType\":\"bytes32\",\"name\":\"e\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"s\",\"type\":\"bytes32\",\"components\":[]}]}],\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"name\":\"execute\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\",\"components\":[]}]},{\"inputs\":[],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"nonce\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\",\"components\":[]}]},{\"inputs\":[],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\",\"components\":[]}]},{\"inputs\":[],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"publicKey\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\",\"components\":[]}]},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_publicKey\",\"type\":\"bytes32\",\"components\":[]}],\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"name\":\"setPublicKey\",\"outputs\":[]},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_publicKey\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"struct Router.RSignature\",\"name\":\"sig\",\"type\":\"tuple\",\"components\":[{\"internalType\":\"bytes32\",\"name\":\"e\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"s\",\"type\":\"bytes32\",\"components\":[]}]}],\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"name\":\"updatePublicKey\",\"outputs\":[]},{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"parity\",\"type\":\"uint8\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"px\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"message\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"e\",\"type\":\"bytes32\",\"components\":[]},{\"internalType\":\"bytes32\",\"name\":\"s\",\"type\":\"bytes32\",\"components\":[]}],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"verify\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\",\"components\":[]}]}]" ;
  #[doc = r" The parsed JSON-ABI of the contract."]
  pub static ROUTER_ABI: ethers::contract::Lazy<ethers::core::abi::Abi> =
    ethers::contract::Lazy::new(|| {
      ethers::core::utils::__serde_json::from_str(__ABI).expect("invalid abi")
    });
  #[doc = r" Bytecode of the #name contract"]
  pub static ROUTER_BYTECODE: ethers::contract::Lazy<ethers::core::types::Bytes> =
    ethers::contract::Lazy::new(|| {
      "0x608060405234801561001057600080fd5b50600160008190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550611412806100696000396000f3fe608060405234801561001057600080fd5b50600436106100935760003560e01c80637e7777a7116100665780637e7777a71461011e5780638da5cb5b1461013c5780639186da4c1461015a578063affed0e01461018a578063e493ef8c146101a857610093565b80631371cd1d146100985780631811024d146100b457806363ffab31146100e457806366123bd814610102575b600080fd5b6100b260048036038101906100ad919061084e565b6101c6565b005b6100ce60048036038101906100c991906109c1565b610295565b6040516100db9190610a3c565b60405180910390f35b6100ec6104e3565b6040516100f99190610a66565b60405180910390f35b61011c60048036038101906101179190610a81565b6104e9565b005b610126610571565b6040516101339190610add565b60405180910390f35b610144610576565b6040516101519190610b39565b60405180910390f35b610174600480360381019061016f9190610b80565b61059c565b6040516101819190610a3c565b60405180910390f35b610192610781565b60405161019f9190610c14565b60405180910390f35b6101b0610787565b6040516101bd9190610c14565b60405180910390f35b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461024d576040517f82b4290000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6000801b6003541461028b576040517f3b3cf97000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b8060038190555050565b600061029f6107ab565b600060025485856040516020016102b893929190610eef565b6040516020818303038152906040528051906020012090506102e8601b600354838660000151876020015161059c565b61031e576040517ffbcb0b3400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b600080600090505b8686905081101561047757600087878381811061034657610345610f21565b5b90506020028101906103589190610f5f565b600001602081019061036a9190610f87565b73ffffffffffffffffffffffffffffffffffffffff1688888481811061039357610392610f21565b5b90506020028101906103a59190610f5f565b602001358989858181106103bc576103bb610f21565b5b90506020028101906103ce9190610f5f565b60400135908a8a868181106103e6576103e5610f21565b5b90506020028101906103f89190610f5f565b80606001906104079190610fb4565b604051610415929190611047565b600060405180830381858888f193505050503d8060008114610453576040519150601f19603f3d011682016040523d82523d6000602084013e610458565b606091505b5050905080821b8317925050808061046f9061108f565b915050610326565b507f6cbfbb9b98ba7bb20bf4e76a5755fce5428cbeb7fdd7cd433fd3d63062476b80600254826040516104ab9291906110d7565b60405180910390a1600260008154809291906104c69061108f565b91905055506000811415925050506104dc6107fa565b9392505050565b60035481565b6000601b836040516020016104ff929190611157565b60405160208183030381529060405280519060200120905061052f601b600354838560000151866020015161059c565b610565576040517ffbcb0b3400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b82600381905550505050565b601b81565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000807ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141806105ce576105cd611183565b5b8660001c8460001c097ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414161060291906111b2565b60001b905060007ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641418061063857610637611183565b5b8760001c8660001c097ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414161066c91906111b2565b60001b90506000801b820361068057600080fd5b60006001838a8a85604051600081526020016040526040516106a594939291906111e6565b6020604051602081039080840390855afa1580156106c7573d6000803e3d6000fd5b505050602060405103519050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603610742576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161073990611288565b60405180910390fd5b808989468a60405160200161075b959493929190611311565b604051602081830303815290604052805190602001208614935050505095945050505050565b60025481565b7ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414181565b6002600054036107f0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016107e7906113bc565b60405180910390fd5b6002600081905550565b6001600081905550565b6000604051905090565b600080fd5b600080fd5b6000819050919050565b61082b81610818565b811461083657600080fd5b50565b60008135905061084881610822565b92915050565b6000602082840312156108645761086361080e565b5b600061087284828501610839565b91505092915050565b600080fd5b600080fd5b600080fd5b60008083601f8401126108a05761089f61087b565b5b8235905067ffffffffffffffff8111156108bd576108bc610880565b5b6020830191508360208202830111156108d9576108d8610885565b5b9250929050565b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61092e826108e5565b810181811067ffffffffffffffff8211171561094d5761094c6108f6565b5b80604052505050565b6000610960610804565b905061096c8282610925565b919050565b600060408284031215610987576109866108e0565b5b6109916040610956565b905060006109a184828501610839565b60008301525060206109b584828501610839565b60208301525092915050565b6000806000606084860312156109da576109d961080e565b5b600084013567ffffffffffffffff8111156109f8576109f7610813565b5b610a048682870161088a565b93509350506020610a1786828701610971565b9150509250925092565b60008115159050919050565b610a3681610a21565b82525050565b6000602082019050610a516000830184610a2d565b92915050565b610a6081610818565b82525050565b6000602082019050610a7b6000830184610a57565b92915050565b60008060608385031215610a9857610a9761080e565b5b6000610aa685828601610839565b9250506020610ab785828601610971565b9150509250929050565b600060ff82169050919050565b610ad781610ac1565b82525050565b6000602082019050610af26000830184610ace565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610b2382610af8565b9050919050565b610b3381610b18565b82525050565b6000602082019050610b4e6000830184610b2a565b92915050565b610b5d81610ac1565b8114610b6857600080fd5b50565b600081359050610b7a81610b54565b92915050565b600080600080600060a08688031215610b9c57610b9b61080e565b5b6000610baa88828901610b6b565b9550506020610bbb88828901610839565b9450506040610bcc88828901610839565b9350506060610bdd88828901610839565b9250506080610bee88828901610839565b9150509295509295909350565b6000819050919050565b610c0e81610bfb565b82525050565b6000602082019050610c296000830184610c05565b92915050565b600082825260208201905092915050565b6000819050919050565b610c5381610b18565b8114610c5e57600080fd5b50565b600081359050610c7081610c4a565b92915050565b6000610c856020840184610c61565b905092915050565b610c9681610b18565b82525050565b610ca581610bfb565b8114610cb057600080fd5b50565b600081359050610cc281610c9c565b92915050565b6000610cd76020840184610cb3565b905092915050565b610ce881610bfb565b82525050565b600080fd5b600080fd5b600080fd5b60008083356001602003843603038112610d1a57610d19610cf8565b5b83810192508235915060208301925067ffffffffffffffff821115610d4257610d41610cee565b5b600182023603831315610d5857610d57610cf3565b5b509250929050565b600082825260208201905092915050565b82818337600083830152505050565b6000610d8c8385610d60565b9350610d99838584610d71565b610da2836108e5565b840190509392505050565b600060808301610dc06000840184610c76565b610dcd6000860182610c8d565b50610ddb6020840184610cc8565b610de86020860182610cdf565b50610df66040840184610cc8565b610e036040860182610cdf565b50610e116060840184610cfd565b8583036060870152610e24838284610d80565b925050508091505092915050565b6000610e3e8383610dad565b905092915050565b600082356001608003833603038112610e6257610e61610cf8565b5b82810191505092915050565b6000602082019050919050565b6000610e878385610c2f565b935083602084028501610e9984610c40565b8060005b87811015610edd578484038952610eb48284610e46565b610ebe8582610e32565b9450610ec983610e6e565b925060208a01995050600181019050610e9d565b50829750879450505050509392505050565b6000604082019050610f046000830186610c05565b8181036020830152610f17818486610e7b565b9050949350505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600080fd5b600080fd5b600080fd5b600082356001608003833603038112610f7b57610f7a610f50565b5b80830191505092915050565b600060208284031215610f9d57610f9c61080e565b5b6000610fab84828501610c61565b91505092915050565b60008083356001602003843603038112610fd157610fd0610f50565b5b80840192508235915067ffffffffffffffff821115610ff357610ff2610f55565b5b60208301925060018202360383131561100f5761100e610f5a565b5b509250929050565b600081905092915050565b600061102e8385611017565b935061103b838584610d71565b82840190509392505050565b6000611054828486611022565b91508190509392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061109a82610bfb565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036110cc576110cb611060565b5b600182019050919050565b60006040820190506110ec6000830185610c05565b6110f96020830184610c05565b9392505050565b60008160f81b9050919050565b600061111882611100565b9050919050565b61113061112b82610ac1565b61110d565b82525050565b6000819050919050565b61115161114c82610818565b611136565b82525050565b6000611163828561111f565b6001820191506111738284611140565b6020820191508190509392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b60006111bd82610bfb565b91506111c883610bfb565b92508282039050818111156111e0576111df611060565b5b92915050565b60006080820190506111fb6000830187610a57565b6112086020830186610ace565b6112156040830185610a57565b6112226060830184610a57565b95945050505050565b600082825260208201905092915050565b7f65637265636f766572206661696c656400000000000000000000000000000000600082015250565b600061127260108361122b565b915061127d8261123c565b602082019050919050565b600060208201905081810360008301526112a181611265565b9050919050565b60008160601b9050919050565b60006112c0826112a8565b9050919050565b60006112d2826112b5565b9050919050565b6112ea6112e582610b18565b6112c7565b82525050565b6000819050919050565b61130b61130682610bfb565b6112f0565b82525050565b600061131d82886112d9565b60148201915061132d828761111f565b60018201915061133d8286611140565b60208201915061134d82856112fa565b60208201915061135d8284611140565b6020820191508190509695505050505050565b7f5265656e7472616e637947756172643a207265656e7472616e742063616c6c00600082015250565b60006113a6601f8361122b565b91506113b182611370565b602082019050919050565b600060208201905081810360008301526113d581611399565b905091905056fea2646970667358221220770dfce1895aa2179484526dc6c7d77f4b7a99d1bc9762f4b53125272824bd0364736f6c63430008110033" . parse () . expect ("invalid bytecode")
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
    #[doc = "Calls the contract's `KEY_PARITY` (0x7e7777a7) function"]
    pub fn key_parity(&self) -> ethers::contract::builders::ContractCall<M, u8> {
      self
        .0
        .method_hash([126, 119, 119, 167], ())
        .expect("method not found (this should never happen)")
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
    pub fn public_key(&self) -> ethers::contract::builders::ContractCall<M, [u8; 32]> {
      self
        .0
        .method_hash([99, 255, 171, 49], ())
        .expect("method not found (this should never happen)")
    }
    #[doc = "Calls the contract's `setPublicKey` (0x1371cd1d) function"]
    pub fn set_public_key(
      &self,
      public_key: [u8; 32],
    ) -> ethers::contract::builders::ContractCall<M, ()> {
      self
        .0
        .method_hash([19, 113, 205, 29], public_key)
        .expect("method not found (this should never happen)")
    }
    #[doc = "Calls the contract's `updatePublicKey` (0x66123bd8) function"]
    pub fn update_public_key(
      &self,
      public_key: [u8; 32],
      sig: Rsignature,
    ) -> ethers::contract::builders::ContractCall<M, ()> {
      self
        .0
        .method_hash([102, 18, 59, 216], (public_key, sig))
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
  #[doc = "Container type for all input parameters for the `KEY_PARITY` function with signature `KEY_PARITY()` and selector `[126, 119, 119, 167]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "KEY_PARITY", abi = "KEY_PARITY()")]
  pub struct KeyParityCall;
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
  #[doc = "Container type for all input parameters for the `setPublicKey` function with signature `setPublicKey(bytes32)` and selector `[19, 113, 205, 29]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "setPublicKey", abi = "setPublicKey(bytes32)")]
  pub struct SetPublicKeyCall {
    pub public_key: [u8; 32],
  }
  #[doc = "Container type for all input parameters for the `updatePublicKey` function with signature `updatePublicKey(bytes32,(bytes32,bytes32))` and selector `[102, 18, 59, 216]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthCall,
    ethers :: contract :: EthDisplay,
    Default,
  )]
  #[ethcall(name = "updatePublicKey", abi = "updatePublicKey(bytes32,(bytes32,bytes32))")]
  pub struct UpdatePublicKeyCall {
    pub public_key: [u8; 32],
    pub sig: Rsignature,
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
    KeyParity(KeyParityCall),
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
      if let Ok(decoded) = <KeyParityCall as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
        return Ok(RouterCalls::KeyParity(decoded));
      }
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
        RouterCalls::KeyParity(element) => element.encode(),
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
        RouterCalls::KeyParity(element) => element.fmt(f),
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
  impl ::std::convert::From<KeyParityCall> for RouterCalls {
    fn from(var: KeyParityCall) -> Self {
      RouterCalls::KeyParity(var)
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
  #[doc = "Container type for all return fields from the `KEY_PARITY` function with signature `KEY_PARITY()` and selector `[126, 119, 119, 167]`"]
  #[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    ethers :: contract :: EthAbiType,
    ethers :: contract :: EthAbiCodec,
    Default,
  )]
  pub struct KeyParityReturn(pub u8);
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
  pub struct PublicKeyReturn(pub [u8; 32]);
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
  #[doc = "`Rsignature(bytes32,bytes32)`"]
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
