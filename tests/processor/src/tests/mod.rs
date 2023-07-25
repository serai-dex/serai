mod key_gen;
pub(crate) use key_gen::key_gen;

mod batch;

pub(crate) const COORDINATORS: usize = 4;
pub(crate) const THRESHOLD: usize = ((COORDINATORS * 2) / 3) + 1;
