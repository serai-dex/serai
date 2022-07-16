use std::{any::TypeId, mem, sync::Once, cell::Cell, boxed::Box, collections::HashMap};

use group::Group;

struct Tables(Cell<mem::MaybeUninit<HashMap<TypeId, *const ()>>>, Once);
static mut TABLES: Tables = Tables(Cell::new(mem::MaybeUninit::uninit()), Once::new());

pub struct Table<G>(Vec<G>);

fn acquire() -> &'static mut HashMap<TypeId, *const ()> {
  unsafe {
    TABLES.1.call_once(|| {
      TABLES.0.set(mem::MaybeUninit::new(HashMap::new()));
    });
    &mut (*(*TABLES.0.as_ptr()).as_mut_ptr())
  }
}

/// This should ONLY be called via the generate_table macro. It is solely public to make said
/// macro work
#[doc(hidden)]
pub fn __unsafe_add_table<G: Group>(table: Table<G>) {
  let tables = acquire();
  if tables.contains_key(&TypeId::of::<G>()) {
    return;
  }

  let ptr = std::ptr::addr_of!(*Box::leak(Box::new(table)));
  unsafe {
    tables.insert(TypeId::of::<G>(), mem::transmute::<*const Table<G>, *const ()>(ptr));
  }
}

macro_rules! generate_table {
  ($G: ident) => {
    __unsafe_add_table(Table(vec![$G::generator()]));
  };
}

/// Returns a table usable for fast multiplication. This will panic if the table was not registered
/// via the generate_table macro
pub fn generator_table<G: Group>() -> &'static Table<G> {
  generate_table!(G);
  unsafe {
    acquire()
      .get(&TypeId::of::<G>())
      .map(|arc| &*mem::transmute::<*const (), *const Table<G>>(*arc))
      .unwrap()
  }
}

#[test]
fn test_static() {
  use k256::ProjectivePoint;
  let table: &'static Table<ProjectivePoint> = generator_table::<ProjectivePoint>();
  dbg!("Read");
  dbg!(table.0.len());
  dbg!(&table.0);
}
