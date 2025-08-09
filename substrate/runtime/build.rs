use substrate_wasm_builder::WasmBuilder;

fn main() {
  WasmBuilder::new()
    .with_current_project()
    .disable_runtime_version_section_check()
    .export_heap_base()
    .import_memory()
    .build()
}
