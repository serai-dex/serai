pub trait OptionExt<T: PartialEq> {
  fn contains(&self, x: &T) -> bool;
}
impl<T: PartialEq> OptionExt<T> for Option<T> {
  fn contains(&self, x: &T) -> bool {
    self.as_ref() == Some(x)
  }
}
