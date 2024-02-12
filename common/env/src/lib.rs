#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

// Obtain a variable from the Serai environment/secret store.
pub fn var(variable: &str) -> Option<String> {
  // TODO: Move this to a proper secret store
  // TODO: Unset this variable
  std::env::var(variable).ok()
}
