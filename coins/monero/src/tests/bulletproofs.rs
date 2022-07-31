use rand::rngs::OsRng;

use crate::{Commitment, random_scalar};
use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint,edwards::CompressedEdwardsY};
//use curve25519_dalek::{edwards::CompressedEdwardsY};
use crate::ringct::bulletproofs::*;
use dalek_ff_group::{EdwardsPoint as ff_EP};

use crate::ringct::bulletproofs::core::OriginalStruct;

use hex_literal::hex;


#[test]
fn bulletproofs() {

    println!("Inside test bulletproofs");
     
    let A: EdwardsPoint = CompressedEdwardsY::from_slice(&hex!("ef32c0b9551b804decdcb107eb22aa715b7ce259bf3c5cac20e24dfa6b28ac71")).decompress().unwrap();
    let S: EdwardsPoint = CompressedEdwardsY::from_slice(&hex!("e1285960861783574ee2b689ae53622834eb0b035d6943103f960cd23e063fa0")).decompress().unwrap();
    let T1: EdwardsPoint = CompressedEdwardsY::from_slice(&hex!("4ea07735f184ba159d0e0eb662bac8cde3eb7d39f31e567b0fbda3aa23fe5620")).decompress().unwrap();
    let T2: EdwardsPoint = CompressedEdwardsY::from_slice(&hex!("b8390aa4b60b255630d40e592f55ec6b7ab5e3a96bfcdcd6f1cd1d2fc95f441e")).decompress().unwrap();
    let a: Scalar = Scalar::from_bytes_mod_order(hex!("0077c5383dea44d3cd1bc74849376bd60679612dc4b945255822457fa0c0a209"));
    let b: Scalar = Scalar::from_bytes_mod_order(hex!("fe80cf5756473482581e1d38644007793ddc66fdeb9404ec1689a907e4863302"));
    let t: Scalar = Scalar::from_bytes_mod_order(hex!("40dfb08e09249040df997851db311bd6827c26e87d6f0f332c55be8eef10e603"));
    let taux: Scalar = Scalar::from_bytes_mod_order(hex!("5957dba8ea9afb23d6e81cc048a92f2d502c10c749dc1b2bd148ae8d41ec7107"));
    let mu: Scalar = Scalar::from_bytes_mod_order(hex!("923023b234c2e64774b820b4961f7181f6c1dc152c438643e5a25b0bf271bc02"));

    let L: Vec<EdwardsPoint> = vec![
                CompressedEdwardsY::from_slice(&hex!("c45f656316b9ebf9d357fb6a9f85b5f09e0b991dd50a6e0ae9b02de3946c9d99")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("9304d2bf0f27183a2acc58cc755a0348da11bd345485fda41b872fee89e72aac")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("1bb8b71925d155dd9569f64129ea049d6149fdc4e7a42a86d9478801d922129b")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("5756a7bf887aa72b9a952f92f47182122e7b19d89e5dd434c747492b00e1c6b7")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("6e497c910d102592830555356af5ff8340e8d141e3fb60ea24cfa587e964f07d")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("f4fa3898e7b08e039183d444f3d55040f3c790ed806cb314de49f3068bdbb218")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("0bbc37597c3ead517a3841e159c8b7b79a5ceaee24b2a9a20350127aab428713")).decompress().unwrap(),
    ];

    let R: Vec<EdwardsPoint> = vec![
                CompressedEdwardsY::from_slice(&hex!("609420ba1702781692e84accfd225adb3d077aedc3cf8125563400466b52dbd9")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("fb4e1d079e7a2b0ec14f7e2a3943bf50b6d60bc346a54fcf562fb234b342abf8")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("6ae3ac97289c48ce95b9c557289e82a34932055f7f5e32720139824fe81b12e5")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("d071cc2ffbdab2d840326ad15f68c01da6482271cae3cf644670d1632f29a15c")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("e52a1754b95e1060589ba7ce0c43d0060820ebfc0d49dc52884bc3c65ad18af5")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("41573b06140108539957df71aceb4b1816d2409ce896659aa5c86f037ca5e851")).decompress().unwrap(),
                CompressedEdwardsY::from_slice(&hex!("a65970b2cc3c7b08b2b5b739dbc8e71e646783c41c625e2a5b1535e3d2e0f742")).decompress().unwrap(),
    ];


    let V: Vec<ff_EP> = vec![
        ff_EP(CompressedEdwardsY::from_slice(&hex!("8e8f23f315edae4f6c2f948d9a861e0ae32d356b933cd11d2f0e031ac744c41f")).decompress().unwrap()),
        ff_EP(CompressedEdwardsY::from_slice(&hex!("2829cbd025aa54cd6e1b59a032564f22f0b2e5627f7f2c4297f90da438b5510f")).decompress().unwrap()),
    ];



    ////This is working for the example above.
    //let struct_bp = Bulletproofs::Original(OriginalStruct{A,S,T1,T2,taux,mu,L,R,a,b,t});
    //assert!(struct_bp.verify(&mut OsRng,V));


    ////This is not working... is the prove function really working or the verify is buggy?
    let commitments = (1 ..= 2).map(|i| Commitment::new(random_scalar(&mut OsRng), i)).collect::<Vec<_>>();
    let Vc: Vec<ff_EP> = commitments.iter().map(|i| ff_EP(Commitment::calculate(i))).collect::<Vec<_>>();
    let bp_proofs = Bulletproofs::prove(&mut OsRng, &commitments,false).unwrap();
    assert!(bp_proofs.verify(&mut OsRng, Vc)); 
    
}

