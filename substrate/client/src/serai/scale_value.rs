use ::scale::Encode;
use scale_info::{MetaType, TypeInfo, Registry, PortableRegistry};

use subxt::ext::scale_value;
pub(crate) use scale_value::Value;
use scale_value::scale;

pub(crate) fn scale_value<V: 'static + Encode + TypeInfo>(value: V) -> Value {
  let mut registry = Registry::new();
  let id = registry.register_type(&MetaType::new::<V>()).id;
  let registry = PortableRegistry::from(registry);
  scale::decode_as_type(&mut value.encode().as_ref(), id, &registry).unwrap().remove_context()
}
