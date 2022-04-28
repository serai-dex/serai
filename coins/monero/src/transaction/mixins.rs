// TOOD
pub(crate) fn select(o: u64) -> (u8, Vec<u64>) {
  let mut mixins: Vec<u64> = (o .. o + 11).into_iter().collect();
  mixins.sort();
  (0, mixins)
}

pub(crate) fn offset(mixins: &[u64]) -> Vec<u64> {
  let mut res = vec![mixins[0]];
  res.resize(11, 0);
  for m in (1 .. mixins.len()).rev() {
    res[m] = mixins[m] - mixins[m - 1];
  }
  res
}
