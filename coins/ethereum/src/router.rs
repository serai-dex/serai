pub use router::*;
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
      "0x608060405234801561001057600080fd5b50600160008190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506114f9806100696000396000f3fe608060405234801561001057600080fd5b50600436106100935760003560e01c80638da5cb5b116100665780638da5cb5b1461011f5780639186da4c1461013d578063affed0e01461016d578063d087d2881461018b578063e493ef8c146101a957610093565b80631811024d1461009857806337088665146100c8578063459e93e5146100e457806363ffab3114610100575b600080fd5b6100b260048036038101906100ad9190610a38565b6101c7565b6040516100bf9190610ab3565b60405180910390f35b6100e260048036038101906100dd9190610b57565b610429565b005b6100fe60048036038101906100f99190610b97565b6104f6565b005b6101086105f1565b604051610116929190610be2565b60405180910390f35b610127610610565b6040516101349190610c4c565b60405180910390f35b61015760048036038101906101529190610c67565b610636565b6040516101649190610ab3565b60405180910390f35b61017561081b565b6040516101829190610cfb565b60405180910390f35b610193610821565b6040516101a09190610cfb565b60405180910390f35b6101b161082b565b6040516101be9190610cfb565b60405180910390f35b60006101d161084f565b600060025485856040516020016101ea93929190610fd6565b60405160208183030381529060405280519060200120905061022e600360000160009054906101000a900460ff166003600101548386600001518760200151610636565b610264576040517ffbcb0b3400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b600080600090505b868690508110156103bd57600087878381811061028c5761028b611008565b5b905060200281019061029e9190611046565b60000160208101906102b0919061106e565b73ffffffffffffffffffffffffffffffffffffffff168888848181106102d9576102d8611008565b5b90506020028101906102eb9190611046565b6020013589898581811061030257610301611008565b5b90506020028101906103149190611046565b60400135908a8a8681811061032c5761032b611008565b5b905060200281019061033e9190611046565b806060019061034d919061109b565b60405161035b92919061112e565b600060405180830381858888f193505050503d8060008114610399576040519150601f19603f3d011682016040523d82523d6000602084013e61039e565b606091505b5050905080821b831792505080806103b590611176565b91505061026c565b507f6cbfbb9b98ba7bb20bf4e76a5755fce5428cbeb7fdd7cd433fd3d63062476b80600254826040516103f19291906111be565b60405180910390a16002600081548092919061040c90611176565b919050555060008114159250505061042261089e565b9392505050565b60008260000151836020015160405160200161044692919061123e565b60405160208183030381529060405280519060200120905061048a600360000160009054906101000a900460ff166003600101548385600001518660200151610636565b6104c0576040517ffbcb0b3400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b82600360008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160010155905050505050565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461057d576040517f82b4290000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6000801b600360010154146105be576040517f3b3cf97000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b8060000151600360000160006101000a81548160ff021916908360ff160217905550806020015160036001018190555050565b60038060000160009054906101000a900460ff16908060010154905082565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000807ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141806106685761066761126a565b5b8660001c8460001c097ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414161069c9190611299565b60001b905060007ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141806106d2576106d161126a565b5b8760001c8660001c097ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641416107069190611299565b60001b90506000801b820361071a57600080fd5b60006001838a8a856040516000815260200160405260405161073f94939291906112cd565b6020604051602081039080840390855afa158015610761573d6000803e3d6000fd5b505050602060405103519050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16036107dc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016107d39061136f565b60405180910390fd5b808989468a6040516020016107f59594939291906113f8565b604051602081830303815290604052805190602001208614935050505095945050505050565b60025481565b6000600254905090565b7ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414181565b600260005403610894576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161088b906114a3565b60405180910390fd5b6002600081905550565b6001600081905550565b6000604051905090565b600080fd5b600080fd5b600080fd5b600080fd5b600080fd5b60008083601f8401126108e1576108e06108bc565b5b8235905067ffffffffffffffff8111156108fe576108fd6108c1565b5b60208301915083602082028301111561091a576109196108c6565b5b9250929050565b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61096f82610926565b810181811067ffffffffffffffff8211171561098e5761098d610937565b5b80604052505050565b60006109a16108a8565b90506109ad8282610966565b919050565b6000819050919050565b6109c5816109b2565b81146109d057600080fd5b50565b6000813590506109e2816109bc565b92915050565b6000604082840312156109fe576109fd610921565b5b610a086040610997565b90506000610a18848285016109d3565b6000830152506020610a2c848285016109d3565b60208301525092915050565b600080600060608486031215610a5157610a506108b2565b5b600084013567ffffffffffffffff811115610a6f57610a6e6108b7565b5b610a7b868287016108cb565b93509350506020610a8e868287016109e8565b9150509250925092565b60008115159050919050565b610aad81610a98565b82525050565b6000602082019050610ac86000830184610aa4565b92915050565b600060ff82169050919050565b610ae481610ace565b8114610aef57600080fd5b50565b600081359050610b0181610adb565b92915050565b600060408284031215610b1d57610b1c610921565b5b610b276040610997565b90506000610b3784828501610af2565b6000830152506020610b4b848285016109d3565b60208301525092915050565b60008060808385031215610b6e57610b6d6108b2565b5b6000610b7c85828601610b07565b9250506040610b8d858286016109e8565b9150509250929050565b600060408284031215610bad57610bac6108b2565b5b6000610bbb84828501610b07565b91505092915050565b610bcd81610ace565b82525050565b610bdc816109b2565b82525050565b6000604082019050610bf76000830185610bc4565b610c046020830184610bd3565b9392505050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610c3682610c0b565b9050919050565b610c4681610c2b565b82525050565b6000602082019050610c616000830184610c3d565b92915050565b600080600080600060a08688031215610c8357610c826108b2565b5b6000610c9188828901610af2565b9550506020610ca2888289016109d3565b9450506040610cb3888289016109d3565b9350506060610cc4888289016109d3565b9250506080610cd5888289016109d3565b9150509295509295909350565b6000819050919050565b610cf581610ce2565b82525050565b6000602082019050610d106000830184610cec565b92915050565b600082825260208201905092915050565b6000819050919050565b610d3a81610c2b565b8114610d4557600080fd5b50565b600081359050610d5781610d31565b92915050565b6000610d6c6020840184610d48565b905092915050565b610d7d81610c2b565b82525050565b610d8c81610ce2565b8114610d9757600080fd5b50565b600081359050610da981610d83565b92915050565b6000610dbe6020840184610d9a565b905092915050565b610dcf81610ce2565b82525050565b600080fd5b600080fd5b600080fd5b60008083356001602003843603038112610e0157610e00610ddf565b5b83810192508235915060208301925067ffffffffffffffff821115610e2957610e28610dd5565b5b600182023603831315610e3f57610e3e610dda565b5b509250929050565b600082825260208201905092915050565b82818337600083830152505050565b6000610e738385610e47565b9350610e80838584610e58565b610e8983610926565b840190509392505050565b600060808301610ea76000840184610d5d565b610eb46000860182610d74565b50610ec26020840184610daf565b610ecf6020860182610dc6565b50610edd6040840184610daf565b610eea6040860182610dc6565b50610ef86060840184610de4565b8583036060870152610f0b838284610e67565b925050508091505092915050565b6000610f258383610e94565b905092915050565b600082356001608003833603038112610f4957610f48610ddf565b5b82810191505092915050565b6000602082019050919050565b6000610f6e8385610d16565b935083602084028501610f8084610d27565b8060005b87811015610fc4578484038952610f9b8284610f2d565b610fa58582610f19565b9450610fb083610f55565b925060208a01995050600181019050610f84565b50829750879450505050509392505050565b6000604082019050610feb6000830186610cec565b8181036020830152610ffe818486610f62565b9050949350505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600080fd5b600080fd5b600080fd5b60008235600160800383360303811261106257611061611037565b5b80830191505092915050565b600060208284031215611084576110836108b2565b5b600061109284828501610d48565b91505092915050565b600080833560016020038436030381126110b8576110b7611037565b5b80840192508235915067ffffffffffffffff8211156110da576110d961103c565b5b6020830192506001820236038313156110f6576110f5611041565b5b509250929050565b600081905092915050565b600061111583856110fe565b9350611122838584610e58565b82840190509392505050565b600061113b828486611109565b91508190509392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061118182610ce2565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036111b3576111b2611147565b5b600182019050919050565b60006040820190506111d36000830185610cec565b6111e06020830184610cec565b9392505050565b60008160f81b9050919050565b60006111ff826111e7565b9050919050565b61121761121282610ace565b6111f4565b82525050565b6000819050919050565b611238611233826109b2565b61121d565b82525050565b600061124a8285611206565b60018201915061125a8284611227565b6020820191508190509392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b60006112a482610ce2565b91506112af83610ce2565b92508282039050818111156112c7576112c6611147565b5b92915050565b60006080820190506112e26000830187610bd3565b6112ef6020830186610bc4565b6112fc6040830185610bd3565b6113096060830184610bd3565b95945050505050565b600082825260208201905092915050565b7f65637265636f766572206661696c656400000000000000000000000000000000600082015250565b6000611359601083611312565b915061136482611323565b602082019050919050565b600060208201905081810360008301526113888161134c565b9050919050565b60008160601b9050919050565b60006113a78261138f565b9050919050565b60006113b98261139c565b9050919050565b6113d16113cc82610c2b565b6113ae565b82525050565b6000819050919050565b6113f26113ed82610ce2565b6113d7565b82525050565b600061140482886113c0565b6014820191506114148287611206565b6001820191506114248286611227565b60208201915061143482856113e1565b6020820191506114448284611227565b6020820191508190509695505050505050565b7f5265656e7472616e637947756172643a207265656e7472616e742063616c6c00600082015250565b600061148d601f83611312565b915061149882611457565b602082019050919050565b600060208201905081810360008301526114bc81611480565b905091905056fea26469706673582212207d6a64af9284e5552b85f0dbd1be2f0d0f978b222c21b684aff4dc43d19df75a64736f6c63430008110033" . parse () . expect ("invalid bytecode")
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
