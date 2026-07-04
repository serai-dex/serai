use core::{
  pin::Pin,
  task::{Poll, Context},
  future::Future,
};

pin_project_lite::pin_project! {
  /// An `or` combination of two futures.
  ///
  /// This returns the value from whichever completes first, with preference given to `F1`. Which
  /// future returned is presented by using `Result` as an `Either` type.
  pub(crate) struct Or<F1, F2> {
    #[pin] pub(crate) f1: F1,
    #[pin] pub(crate) f2: F2,
  }
}

impl<F1: Future, F2: Future> Future for Or<F1, F2> {
  type Output = Result<F1::Output, F2::Output>;
  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let futures = self.as_mut().project();
    match futures.f1.poll(cx) {
      Poll::Pending => {}
      Poll::Ready(value) => return Poll::Ready(Ok(value)),
    }
    match futures.f2.poll(cx) {
      Poll::Pending => {}
      Poll::Ready(value) => return Poll::Ready(Err(value)),
    }
    Poll::Pending
  }
}
