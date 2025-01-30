/// Strip the modules from a type name.
// This may be of the form `a::b::C`, in which case we only want `C`
pub(crate) fn strip_type_name(full_type_name: &'static str) -> String {
  // It also may be `a::b::C<d::e::F>`, in which case, we only attempt to strip `a::b`
  let mut by_generics = full_type_name.split('<');

  // Strip to just `C`
  let full_outer_object_name = by_generics.next().unwrap();
  let mut outer_object_name_parts = full_outer_object_name.split("::");
  let mut last_part_in_outer_object_name = outer_object_name_parts.next().unwrap();
  for part in outer_object_name_parts {
    last_part_in_outer_object_name = part;
  }

  // Push back on the generic terms
  let mut type_name = last_part_in_outer_object_name.to_string();
  for generic in by_generics {
    type_name.push('<');
    type_name.push_str(generic);
  }
  type_name
}

#[test]
fn test_strip_type_name() {
  assert_eq!(strip_type_name("core::option::Option"), "Option");
  assert_eq!(
    strip_type_name("core::option::Option<alloc::string::String>"),
    "Option<alloc::string::String>"
  );
}
