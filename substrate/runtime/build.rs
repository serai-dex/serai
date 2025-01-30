use substrate_wasm_builder::WasmBuilder;

fn main() {
  WasmBuilder::new()
    .with_current_project()
    // https://substrate.stackexchange.com/questions/12124
    // TODO: Remove once we've moved to polkadot-sdk
    .disable_runtime_version_section_check()
    .export_heap_base()
    .import_memory()
    .build()
}
