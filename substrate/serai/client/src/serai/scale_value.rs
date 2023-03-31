use ::scale::Encode;
use scale_info::{MetaType, TypeInfo, Registry, PortableRegistry};
use subxt::ext::scale_value::{Composite, ValueDef, Value, scale};

pub(crate) fn scale_value<V: 'static + Encode + TypeInfo>(value: V) -> Value {
  let mut registry = Registry::new();
  let id = registry.register_type(&MetaType::new::<V>()).id;
  let registry = PortableRegistry::from(registry);
  scale::decode_as_type(&mut value.encode().as_ref(), id, &registry).unwrap().remove_context()
}

pub(crate) fn scale_composite<V: 'static + Encode + TypeInfo>(value: V) -> Composite<()> {
  match scale_value(value).value {
    ValueDef::Composite(composite) => composite,
    ValueDef::Variant(variant) => variant.values,
    _ => panic!("not composite"),
  }
}
