#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use core::any::{TypeId, Any};

use std::{
  thread::{self, ThreadId},
  sync::RwLock,
  collections::HashMap,
};

use group::Group;

type Stack = Option<HashMap<ThreadId, HashMap<TypeId, Vec<Box<dyn Any>>>>>;
static mut GENERATORS: RwLock<Stack> = RwLock::new(None);

fn stack<G: Group>(map: &mut Stack) -> &mut Vec<Box<dyn Any>> {
  map
    .get_or_insert_with(HashMap::new)
    .entry(thread::current().id())
    .or_insert(HashMap::new())
    .entry(TypeId::of::<G>())
    .or_insert(Vec::new())
}

#[doc(hidden)]
pub fn push<G: Group>(generator: G) {
  stack::<G>(&mut unsafe { GENERATORS.write() }.unwrap()).push(Box::new(generator));
}

#[doc(hidden)]
pub fn pop<G: Group>() {
  stack::<G>(&mut unsafe { GENERATORS.write() }.unwrap()).pop().unwrap();
}

#[doc(hidden)]
fn get<G: Group>() {
  stack::<G>(&mut unsafe { GENERATORS.write() }.unwrap()).get(0).unwrap_or(G::generator());
}

macro_rules! dynamic_generator {
  ($Name: ident, $Base: ident, $generator: expr) => {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct $Name($Base);
  }
}

// type G: Group<Scalar = Self::F> + GroupOps + PrimeGroup + Zeroize + ConstantTimeEq;
macro_rules! complete_dynamic_generator {
  ($Name: ident, $Base: ident, $generator: expr) => {
    #[derive(Clone, Copy, PartialEq, Eq, Debug, ConstantTimeEq, Zeroize)]
    struct $Name($Base);
    impl Group for DynamicGenerator {}
    impl GroupEncoding for DynamicGenerator {}
    impl PrimeGroup for DynamicGenerator {}
  }
}

/*
struct DynamicGenerator<G: Group> { _phantom: PhantomData<G> }
impl DynamicGenerator {}
*/
