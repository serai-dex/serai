#[macro_export]
macro_rules! lazy_static {
  ($($(#[$attr: meta])* $vis: vis static ref $name: ident: $type: ty = $value: expr;)*) => {
    $(
      $(#[$attr])*
      $vis static $name: std::sync::LazyLock<$type> = std::sync::LazyLock::new(|| $value);
    )*
  }
}

/// Explicitly initialize a static declared with [`lazy_static`].
pub fn initialize<T, F: Fn() -> T>(lazy: &std::sync::LazyLock<T, F>) {
  std::sync::LazyLock::force(lazy);
}
