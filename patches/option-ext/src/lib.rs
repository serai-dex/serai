pub trait OptionExt<T> {
  fn contains(&self, x: &T) -> bool where T: PartialEq;
}
impl<T> OptionExt<T> for Option<T> {
  fn contains(&self, x: &T) -> bool where T: PartialEq {
    self.as_ref() == Some(x)
  }
}
