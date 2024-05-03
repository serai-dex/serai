pub use router::*;
/// This module was auto-generated with ethers-rs Abigen.
/// More information at: <https://github.com/gakonst/ethers-rs>
#[allow(
    clippy::enum_variant_names,
    clippy::too_many_arguments,
    clippy::upper_case_acronyms,
    clippy::type_complexity,
    dead_code,
    non_camel_case_types,
)]
pub mod router {
    #[allow(deprecated)]
    fn __abi() -> ::ethers_core::abi::Abi {
        ::ethers_core::abi::ethabi::Contract {
            constructor: ::core::option::Option::Some(::ethers_core::abi::ethabi::Constructor {
                inputs: ::std::vec![],
            }),
            functions: ::core::convert::From::from([
                (
                    ::std::borrow::ToOwned::to_owned("KEY_PARITY"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("KEY_PARITY"),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Uint(8usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint8"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers_core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("Q"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("Q"),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Uint(256usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint256"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers_core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("execute"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("execute"),
                            inputs: ::std::vec![
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("transactions"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Array(
                                        ::std::boxed::Box::new(
                                            ::ethers_core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers_core::abi::ethabi::ParamType::Address,
                                                    ::ethers_core::abi::ethabi::ParamType::Uint(256usize),
                                                    ::ethers_core::abi::ethabi::ParamType::Bytes,
                                                ],
                                            ),
                                        ),
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct Router.OutInstruction[]",
                                        ),
                                    ),
                                },
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("sig"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers_core::abi::ethabi::ParamType::FixedBytes(32usize),
                                            ::ethers_core::abi::ethabi::ParamType::FixedBytes(32usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct Router.Signature"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers_core::abi::ethabi::StateMutability::NonPayable,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("initSeraiKey"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("initSeraiKey"),
                            inputs: ::std::vec![
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("_seraiKey"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers_core::abi::ethabi::StateMutability::NonPayable,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("initializer"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("initializer"),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Address,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("address"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers_core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("nonce"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("nonce"),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Uint(256usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint256"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers_core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("seraiKey"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("seraiKey"),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers_core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers_core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("updateSeraiKey"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("updateSeraiKey"),
                            inputs: ::std::vec![
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("_seraiKey"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("sig"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers_core::abi::ethabi::ParamType::FixedBytes(32usize),
                                            ::ethers_core::abi::ethabi::ParamType::FixedBytes(32usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct Router.Signature"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers_core::abi::ethabi::StateMutability::NonPayable,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("verify"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("verify"),
                            inputs: ::std::vec![
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("parity"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Uint(8usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint8"),
                                    ),
                                },
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("px"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("message"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("c"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("s"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers_core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Bool,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bool"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers_core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
            ]),
            events: ::core::convert::From::from([
                (
                    ::std::borrow::ToOwned::to_owned("Executed"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::Event {
                            name: ::std::borrow::ToOwned::to_owned("Executed"),
                            inputs: ::std::vec![
                                ::ethers_core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("nonce"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Uint(256usize),
                                    indexed: false,
                                },
                                ::ethers_core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("batch"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    indexed: false,
                                },
                                ::ethers_core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("success"),
                                    kind: ::ethers_core::abi::ethabi::ParamType::Uint(256usize),
                                    indexed: false,
                                },
                            ],
                            anonymous: false,
                        },
                    ],
                ),
            ]),
            errors: ::core::convert::From::from([
                (
                    ::std::borrow::ToOwned::to_owned("AlreadyInitialized"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::AbiError {
                            name: ::std::borrow::ToOwned::to_owned("AlreadyInitialized"),
                            inputs: ::std::vec![],
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("InvalidKey"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::AbiError {
                            name: ::std::borrow::ToOwned::to_owned("InvalidKey"),
                            inputs: ::std::vec![],
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("InvalidSOrA"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::AbiError {
                            name: ::std::borrow::ToOwned::to_owned("InvalidSOrA"),
                            inputs: ::std::vec![],
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("InvalidSignature"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::AbiError {
                            name: ::std::borrow::ToOwned::to_owned("InvalidSignature"),
                            inputs: ::std::vec![],
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("NotInitializer"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::AbiError {
                            name: ::std::borrow::ToOwned::to_owned("NotInitializer"),
                            inputs: ::std::vec![],
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("TooManyTransactions"),
                    ::std::vec![
                        ::ethers_core::abi::ethabi::AbiError {
                            name: ::std::borrow::ToOwned::to_owned(
                                "TooManyTransactions",
                            ),
                            inputs: ::std::vec![],
                        },
                    ],
                ),
            ]),
            receive: false,
            fallback: false,
        }
    }
    ///The parsed JSON ABI of the contract.
    pub static ROUTER_ABI: ::ethers_contract::Lazy<::ethers_core::abi::Abi> = ::ethers_contract::Lazy::new(
        __abi,
    );
    pub struct Router<M>(::ethers_contract::Contract<M>);
    impl<M> ::core::clone::Clone for Router<M> {
        fn clone(&self) -> Self {
            Self(::core::clone::Clone::clone(&self.0))
        }
    }
    impl<M> ::core::ops::Deref for Router<M> {
        type Target = ::ethers_contract::Contract<M>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl<M> ::core::ops::DerefMut for Router<M> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
    impl<M> ::core::fmt::Debug for Router<M> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            f.debug_tuple(::core::stringify!(Router)).field(&self.address()).finish()
        }
    }
    impl<M: ::ethers_providers::Middleware> Router<M> {
        /// Creates a new contract instance with the specified `ethers` client at
        /// `address`. The contract derefs to a `ethers::Contract` object.
        pub fn new<T: Into<::ethers_core::types::Address>>(
            address: T,
            client: ::std::sync::Arc<M>,
        ) -> Self {
            Self(
                ::ethers_contract::Contract::new(
                    address.into(),
                    ROUTER_ABI.clone(),
                    client,
                ),
            )
        }
        ///Calls the contract's `KEY_PARITY` (0x7e7777a7) function
        pub fn key_parity(&self) -> ::ethers_contract::builders::ContractCall<M, u8> {
            self.0
                .method_hash([126, 119, 119, 167], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `Q` (0xe493ef8c) function
        pub fn q(
            &self,
        ) -> ::ethers_contract::builders::ContractCall<M, ::ethers_core::types::U256> {
            self.0
                .method_hash([228, 147, 239, 140], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `execute` (0xb839b1a1) function
        pub fn execute(
            &self,
            transactions: ::std::vec::Vec<OutInstruction>,
            sig: Signature,
        ) -> ::ethers_contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([184, 57, 177, 161], (transactions, sig))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `initSeraiKey` (0x3d54f51e) function
        pub fn init_serai_key(
            &self,
            serai_key: [u8; 32],
        ) -> ::ethers_contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([61, 84, 245, 30], serai_key)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `initializer` (0x9ce110d7) function
        pub fn initializer(
            &self,
        ) -> ::ethers_contract::builders::ContractCall<
            M,
            ::ethers_core::types::Address,
        > {
            self.0
                .method_hash([156, 225, 16, 215], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `nonce` (0xaffed0e0) function
        pub fn nonce(
            &self,
        ) -> ::ethers_contract::builders::ContractCall<M, ::ethers_core::types::U256> {
            self.0
                .method_hash([175, 254, 208, 224], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `seraiKey` (0x9d6eea0a) function
        pub fn serai_key(
            &self,
        ) -> ::ethers_contract::builders::ContractCall<M, [u8; 32]> {
            self.0
                .method_hash([157, 110, 234, 10], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `updateSeraiKey` (0xb5071c6a) function
        pub fn update_serai_key(
            &self,
            serai_key: [u8; 32],
            sig: Signature,
        ) -> ::ethers_contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([181, 7, 28, 106], (serai_key, sig))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `verify` (0x9186da4c) function
        pub fn verify(
            &self,
            parity: u8,
            px: [u8; 32],
            message: [u8; 32],
            c: [u8; 32],
            s: [u8; 32],
        ) -> ::ethers_contract::builders::ContractCall<M, bool> {
            self.0
                .method_hash([145, 134, 218, 76], (parity, px, message, c, s))
                .expect("method not found (this should never happen)")
        }
        ///Gets the contract's `Executed` event
        pub fn executed_filter(
            &self,
        ) -> ::ethers_contract::builders::Event<::std::sync::Arc<M>, M, ExecutedFilter> {
            self.0.event()
        }
        /// Returns an `Event` builder for all the events of this contract.
        pub fn events(
            &self,
        ) -> ::ethers_contract::builders::Event<::std::sync::Arc<M>, M, ExecutedFilter> {
            self.0.event_with_filter(::core::default::Default::default())
        }
    }
    impl<M: ::ethers_providers::Middleware> From<::ethers_contract::Contract<M>>
    for Router<M> {
        fn from(contract: ::ethers_contract::Contract<M>) -> Self {
            Self::new(contract.address(), contract.client())
        }
    }
    ///Custom Error type `AlreadyInitialized` with signature `AlreadyInitialized()` and selector `0x0dc149f0`
    #[derive(
        Clone,
        ::ethers_contract::EthError,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[etherror(name = "AlreadyInitialized", abi = "AlreadyInitialized()")]
    pub struct AlreadyInitialized;
    ///Custom Error type `InvalidKey` with signature `InvalidKey()` and selector `0x76d4e1e8`
    #[derive(
        Clone,
        ::ethers_contract::EthError,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[etherror(name = "InvalidKey", abi = "InvalidKey()")]
    pub struct InvalidKey;
    ///Custom Error type `InvalidSOrA` with signature `InvalidSOrA()` and selector `0x4e99a12e`
    #[derive(
        Clone,
        ::ethers_contract::EthError,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[etherror(name = "InvalidSOrA", abi = "InvalidSOrA()")]
    pub struct InvalidSOrA;
    ///Custom Error type `InvalidSignature` with signature `InvalidSignature()` and selector `0x8baa579f`
    #[derive(
        Clone,
        ::ethers_contract::EthError,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[etherror(name = "InvalidSignature", abi = "InvalidSignature()")]
    pub struct InvalidSignature;
    ///Custom Error type `NotInitializer` with signature `NotInitializer()` and selector `0xceeb95b3`
    #[derive(
        Clone,
        ::ethers_contract::EthError,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[etherror(name = "NotInitializer", abi = "NotInitializer()")]
    pub struct NotInitializer;
    ///Custom Error type `TooManyTransactions` with signature `TooManyTransactions()` and selector `0xfb4593ba`
    #[derive(
        Clone,
        ::ethers_contract::EthError,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[etherror(name = "TooManyTransactions", abi = "TooManyTransactions()")]
    pub struct TooManyTransactions;
    ///Container type for all of the contract's custom errors
    #[derive(Clone, ::ethers_contract::EthAbiType, Debug, PartialEq, Eq, Hash)]
    pub enum RouterErrors {
        AlreadyInitialized(AlreadyInitialized),
        InvalidKey(InvalidKey),
        InvalidSOrA(InvalidSOrA),
        InvalidSignature(InvalidSignature),
        NotInitializer(NotInitializer),
        TooManyTransactions(TooManyTransactions),
        /// The standard solidity revert string, with selector
        /// Error(string) -- 0x08c379a0
        RevertString(::std::string::String),
    }
    impl ::ethers_core::abi::AbiDecode for RouterErrors {
        fn decode(
            data: impl AsRef<[u8]>,
        ) -> ::core::result::Result<Self, ::ethers_core::abi::AbiError> {
            let data = data.as_ref();
            if let Ok(decoded) = <::std::string::String as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::RevertString(decoded));
            }
            if let Ok(decoded) = <AlreadyInitialized as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::AlreadyInitialized(decoded));
            }
            if let Ok(decoded) = <InvalidKey as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::InvalidKey(decoded));
            }
            if let Ok(decoded) = <InvalidSOrA as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::InvalidSOrA(decoded));
            }
            if let Ok(decoded) = <InvalidSignature as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::InvalidSignature(decoded));
            }
            if let Ok(decoded) = <NotInitializer as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::NotInitializer(decoded));
            }
            if let Ok(decoded) = <TooManyTransactions as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::TooManyTransactions(decoded));
            }
            Err(::ethers_core::abi::Error::InvalidData.into())
        }
    }
    impl ::ethers_core::abi::AbiEncode for RouterErrors {
        fn encode(self) -> ::std::vec::Vec<u8> {
            match self {
                Self::AlreadyInitialized(element) => {
                    ::ethers_core::abi::AbiEncode::encode(element)
                }
                Self::InvalidKey(element) => {
                    ::ethers_core::abi::AbiEncode::encode(element)
                }
                Self::InvalidSOrA(element) => {
                    ::ethers_core::abi::AbiEncode::encode(element)
                }
                Self::InvalidSignature(element) => {
                    ::ethers_core::abi::AbiEncode::encode(element)
                }
                Self::NotInitializer(element) => {
                    ::ethers_core::abi::AbiEncode::encode(element)
                }
                Self::TooManyTransactions(element) => {
                    ::ethers_core::abi::AbiEncode::encode(element)
                }
                Self::RevertString(s) => ::ethers_core::abi::AbiEncode::encode(s),
            }
        }
    }
    impl ::ethers_contract::ContractRevert for RouterErrors {
        fn valid_selector(selector: [u8; 4]) -> bool {
            match selector {
                [0x08, 0xc3, 0x79, 0xa0] => true,
                _ if selector
                    == <AlreadyInitialized as ::ethers_contract::EthError>::selector() => {
                    true
                }
                _ if selector
                    == <InvalidKey as ::ethers_contract::EthError>::selector() => true,
                _ if selector
                    == <InvalidSOrA as ::ethers_contract::EthError>::selector() => true,
                _ if selector
                    == <InvalidSignature as ::ethers_contract::EthError>::selector() => {
                    true
                }
                _ if selector
                    == <NotInitializer as ::ethers_contract::EthError>::selector() => {
                    true
                }
                _ if selector
                    == <TooManyTransactions as ::ethers_contract::EthError>::selector() => {
                    true
                }
                _ => false,
            }
        }
    }
    impl ::core::fmt::Display for RouterErrors {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
                Self::AlreadyInitialized(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::InvalidKey(element) => ::core::fmt::Display::fmt(element, f),
                Self::InvalidSOrA(element) => ::core::fmt::Display::fmt(element, f),
                Self::InvalidSignature(element) => ::core::fmt::Display::fmt(element, f),
                Self::NotInitializer(element) => ::core::fmt::Display::fmt(element, f),
                Self::TooManyTransactions(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::RevertString(s) => ::core::fmt::Display::fmt(s, f),
            }
        }
    }
    impl ::core::convert::From<::std::string::String> for RouterErrors {
        fn from(value: String) -> Self {
            Self::RevertString(value)
        }
    }
    impl ::core::convert::From<AlreadyInitialized> for RouterErrors {
        fn from(value: AlreadyInitialized) -> Self {
            Self::AlreadyInitialized(value)
        }
    }
    impl ::core::convert::From<InvalidKey> for RouterErrors {
        fn from(value: InvalidKey) -> Self {
            Self::InvalidKey(value)
        }
    }
    impl ::core::convert::From<InvalidSOrA> for RouterErrors {
        fn from(value: InvalidSOrA) -> Self {
            Self::InvalidSOrA(value)
        }
    }
    impl ::core::convert::From<InvalidSignature> for RouterErrors {
        fn from(value: InvalidSignature) -> Self {
            Self::InvalidSignature(value)
        }
    }
    impl ::core::convert::From<NotInitializer> for RouterErrors {
        fn from(value: NotInitializer) -> Self {
            Self::NotInitializer(value)
        }
    }
    impl ::core::convert::From<TooManyTransactions> for RouterErrors {
        fn from(value: TooManyTransactions) -> Self {
            Self::TooManyTransactions(value)
        }
    }
    #[derive(
        Clone,
        ::ethers_contract::EthEvent,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethevent(name = "Executed", abi = "Executed(uint256,bytes32,uint256)")]
    pub struct ExecutedFilter {
        pub nonce: ::ethers_core::types::U256,
        pub batch: [u8; 32],
        pub success: ::ethers_core::types::U256,
    }
    ///Container type for all input parameters for the `KEY_PARITY` function with signature `KEY_PARITY()` and selector `0x7e7777a7`
    #[derive(
        Clone,
        ::ethers_contract::EthCall,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "KEY_PARITY", abi = "KEY_PARITY()")]
    pub struct KeyParityCall;
    ///Container type for all input parameters for the `Q` function with signature `Q()` and selector `0xe493ef8c`
    #[derive(
        Clone,
        ::ethers_contract::EthCall,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "Q", abi = "Q()")]
    pub struct QCall;
    ///Container type for all input parameters for the `execute` function with signature `execute((address,uint256,bytes)[],(bytes32,bytes32))` and selector `0xb839b1a1`
    #[derive(
        Clone,
        ::ethers_contract::EthCall,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "execute",
        abi = "execute((address,uint256,bytes)[],(bytes32,bytes32))"
    )]
    pub struct ExecuteCall {
        pub transactions: ::std::vec::Vec<OutInstruction>,
        pub sig: Signature,
    }
    ///Container type for all input parameters for the `initSeraiKey` function with signature `initSeraiKey(bytes32)` and selector `0x3d54f51e`
    #[derive(
        Clone,
        ::ethers_contract::EthCall,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "initSeraiKey", abi = "initSeraiKey(bytes32)")]
    pub struct InitSeraiKeyCall {
        pub serai_key: [u8; 32],
    }
    ///Container type for all input parameters for the `initializer` function with signature `initializer()` and selector `0x9ce110d7`
    #[derive(
        Clone,
        ::ethers_contract::EthCall,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "initializer", abi = "initializer()")]
    pub struct InitializerCall;
    ///Container type for all input parameters for the `nonce` function with signature `nonce()` and selector `0xaffed0e0`
    #[derive(
        Clone,
        ::ethers_contract::EthCall,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "nonce", abi = "nonce()")]
    pub struct NonceCall;
    ///Container type for all input parameters for the `seraiKey` function with signature `seraiKey()` and selector `0x9d6eea0a`
    #[derive(
        Clone,
        ::ethers_contract::EthCall,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "seraiKey", abi = "seraiKey()")]
    pub struct SeraiKeyCall;
    ///Container type for all input parameters for the `updateSeraiKey` function with signature `updateSeraiKey(bytes32,(bytes32,bytes32))` and selector `0xb5071c6a`
    #[derive(
        Clone,
        ::ethers_contract::EthCall,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "updateSeraiKey",
        abi = "updateSeraiKey(bytes32,(bytes32,bytes32))"
    )]
    pub struct UpdateSeraiKeyCall {
        pub serai_key: [u8; 32],
        pub sig: Signature,
    }
    ///Container type for all input parameters for the `verify` function with signature `verify(uint8,bytes32,bytes32,bytes32,bytes32)` and selector `0x9186da4c`
    #[derive(
        Clone,
        ::ethers_contract::EthCall,
        ::ethers_contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "verify", abi = "verify(uint8,bytes32,bytes32,bytes32,bytes32)")]
    pub struct VerifyCall {
        pub parity: u8,
        pub px: [u8; 32],
        pub message: [u8; 32],
        pub c: [u8; 32],
        pub s: [u8; 32],
    }
    ///Container type for all of the contract's call
    #[derive(Clone, ::ethers_contract::EthAbiType, Debug, PartialEq, Eq, Hash)]
    pub enum RouterCalls {
        KeyParity(KeyParityCall),
        Q(QCall),
        Execute(ExecuteCall),
        InitSeraiKey(InitSeraiKeyCall),
        Initializer(InitializerCall),
        Nonce(NonceCall),
        SeraiKey(SeraiKeyCall),
        UpdateSeraiKey(UpdateSeraiKeyCall),
        Verify(VerifyCall),
    }
    impl ::ethers_core::abi::AbiDecode for RouterCalls {
        fn decode(
            data: impl AsRef<[u8]>,
        ) -> ::core::result::Result<Self, ::ethers_core::abi::AbiError> {
            let data = data.as_ref();
            if let Ok(decoded) = <KeyParityCall as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::KeyParity(decoded));
            }
            if let Ok(decoded) = <QCall as ::ethers_core::abi::AbiDecode>::decode(data) {
                return Ok(Self::Q(decoded));
            }
            if let Ok(decoded) = <ExecuteCall as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::Execute(decoded));
            }
            if let Ok(decoded) = <InitSeraiKeyCall as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::InitSeraiKey(decoded));
            }
            if let Ok(decoded) = <InitializerCall as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::Initializer(decoded));
            }
            if let Ok(decoded) = <NonceCall as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::Nonce(decoded));
            }
            if let Ok(decoded) = <SeraiKeyCall as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::SeraiKey(decoded));
            }
            if let Ok(decoded) = <UpdateSeraiKeyCall as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::UpdateSeraiKey(decoded));
            }
            if let Ok(decoded) = <VerifyCall as ::ethers_core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::Verify(decoded));
            }
            Err(::ethers_core::abi::Error::InvalidData.into())
        }
    }
    impl ::ethers_core::abi::AbiEncode for RouterCalls {
        fn encode(self) -> Vec<u8> {
            match self {
                Self::KeyParity(element) => {
                    ::ethers_core::abi::AbiEncode::encode(element)
                }
                Self::Q(element) => ::ethers_core::abi::AbiEncode::encode(element),
                Self::Execute(element) => ::ethers_core::abi::AbiEncode::encode(element),
                Self::InitSeraiKey(element) => {
                    ::ethers_core::abi::AbiEncode::encode(element)
                }
                Self::Initializer(element) => {
                    ::ethers_core::abi::AbiEncode::encode(element)
                }
                Self::Nonce(element) => ::ethers_core::abi::AbiEncode::encode(element),
                Self::SeraiKey(element) => ::ethers_core::abi::AbiEncode::encode(element),
                Self::UpdateSeraiKey(element) => {
                    ::ethers_core::abi::AbiEncode::encode(element)
                }
                Self::Verify(element) => ::ethers_core::abi::AbiEncode::encode(element),
            }
        }
    }
    impl ::core::fmt::Display for RouterCalls {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
                Self::KeyParity(element) => ::core::fmt::Display::fmt(element, f),
                Self::Q(element) => ::core::fmt::Display::fmt(element, f),
                Self::Execute(element) => ::core::fmt::Display::fmt(element, f),
                Self::InitSeraiKey(element) => ::core::fmt::Display::fmt(element, f),
                Self::Initializer(element) => ::core::fmt::Display::fmt(element, f),
                Self::Nonce(element) => ::core::fmt::Display::fmt(element, f),
                Self::SeraiKey(element) => ::core::fmt::Display::fmt(element, f),
                Self::UpdateSeraiKey(element) => ::core::fmt::Display::fmt(element, f),
                Self::Verify(element) => ::core::fmt::Display::fmt(element, f),
            }
        }
    }
    impl ::core::convert::From<KeyParityCall> for RouterCalls {
        fn from(value: KeyParityCall) -> Self {
            Self::KeyParity(value)
        }
    }
    impl ::core::convert::From<QCall> for RouterCalls {
        fn from(value: QCall) -> Self {
            Self::Q(value)
        }
    }
    impl ::core::convert::From<ExecuteCall> for RouterCalls {
        fn from(value: ExecuteCall) -> Self {
            Self::Execute(value)
        }
    }
    impl ::core::convert::From<InitSeraiKeyCall> for RouterCalls {
        fn from(value: InitSeraiKeyCall) -> Self {
            Self::InitSeraiKey(value)
        }
    }
    impl ::core::convert::From<InitializerCall> for RouterCalls {
        fn from(value: InitializerCall) -> Self {
            Self::Initializer(value)
        }
    }
    impl ::core::convert::From<NonceCall> for RouterCalls {
        fn from(value: NonceCall) -> Self {
            Self::Nonce(value)
        }
    }
    impl ::core::convert::From<SeraiKeyCall> for RouterCalls {
        fn from(value: SeraiKeyCall) -> Self {
            Self::SeraiKey(value)
        }
    }
    impl ::core::convert::From<UpdateSeraiKeyCall> for RouterCalls {
        fn from(value: UpdateSeraiKeyCall) -> Self {
            Self::UpdateSeraiKey(value)
        }
    }
    impl ::core::convert::From<VerifyCall> for RouterCalls {
        fn from(value: VerifyCall) -> Self {
            Self::Verify(value)
        }
    }
    ///Container type for all return fields from the `KEY_PARITY` function with signature `KEY_PARITY()` and selector `0x7e7777a7`
    #[derive(
        Clone,
        ::ethers_contract::EthAbiType,
        ::ethers_contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct KeyParityReturn(pub u8);
    ///Container type for all return fields from the `Q` function with signature `Q()` and selector `0xe493ef8c`
    #[derive(
        Clone,
        ::ethers_contract::EthAbiType,
        ::ethers_contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct QReturn(pub ::ethers_core::types::U256);
    ///Container type for all return fields from the `initializer` function with signature `initializer()` and selector `0x9ce110d7`
    #[derive(
        Clone,
        ::ethers_contract::EthAbiType,
        ::ethers_contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct InitializerReturn(pub ::ethers_core::types::Address);
    ///Container type for all return fields from the `nonce` function with signature `nonce()` and selector `0xaffed0e0`
    #[derive(
        Clone,
        ::ethers_contract::EthAbiType,
        ::ethers_contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct NonceReturn(pub ::ethers_core::types::U256);
    ///Container type for all return fields from the `seraiKey` function with signature `seraiKey()` and selector `0x9d6eea0a`
    #[derive(
        Clone,
        ::ethers_contract::EthAbiType,
        ::ethers_contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct SeraiKeyReturn(pub [u8; 32]);
    ///Container type for all return fields from the `verify` function with signature `verify(uint8,bytes32,bytes32,bytes32,bytes32)` and selector `0x9186da4c`
    #[derive(
        Clone,
        ::ethers_contract::EthAbiType,
        ::ethers_contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct VerifyReturn(pub bool);
    ///`OutInstruction(address,uint256,bytes)`
    #[derive(
        Clone,
        ::ethers_contract::EthAbiType,
        ::ethers_contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct OutInstruction {
        pub to: ::ethers_core::types::Address,
        pub value: ::ethers_core::types::U256,
        pub data: ::ethers_core::types::Bytes,
    }
    ///`Signature(bytes32,bytes32)`
    #[derive(
        Clone,
        ::ethers_contract::EthAbiType,
        ::ethers_contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct Signature {
        pub c: [u8; 32],
        pub s: [u8; 32],
    }
}
