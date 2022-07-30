// TODO: https://github.com/paritytech/subxt/issues/602
// const METADATA: &str = concat!(env!("OUT_DIR"), "serai.scale");

#[subxt::subxt(runtime_metadata_path = "serai.scale")]
pub mod runtime {}
