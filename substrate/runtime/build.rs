fn main() {
  #[cfg(not(target_family = "wasm"))]
  substrate_wasm_builder::WasmBuilder::build_using_defaults();
}
