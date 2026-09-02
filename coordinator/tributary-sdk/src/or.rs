use core::{
  pin::Pin,
  task::{Poll, Context},
  future::Future,
};

pub(crate) enum Either<L, R> {
  L(L),
  R(R),
}

pin_project_lite::pin_project! {
  /// An `or` combination of two futures.
  ///
  /// This returns the value from whichever completes first, with preference given to `F1`. The
  /// other future will be dropped (cancelled). Both futures must be cancel-safe accordingly.
  pub(crate) struct Or<F1, F2> {
    #[pin] pub(crate) f1: F1,
    #[pin] pub(crate) f2: F2,
  }
}

impl<F1: Future, F2: Future> Future for Or<F1, F2> {
  type Output = Either<F1::Output, F2::Output>;
  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let futures = self.as_mut().project();
    match futures.f1.poll(cx) {
      Poll::Pending => {}
      Poll::Ready(value) => return Poll::Ready(Either::L(value)),
    }
    match futures.f2.poll(cx) {
      Poll::Pending => {}
      Poll::Ready(value) => return Poll::Ready(Either::R(value)),
    }
    Poll::Pending
  }
}

#[test]
fn or() {
  use core::{pin::pin, task::Waker, future};

  let mut context = Context::from_waker(Waker::noop());

  assert!(matches!(
    pin!(Or { f1: future::ready(()), f2: future::pending::<()>() }).poll(&mut context),
    Poll::Ready(Either::L(()))
  ));
  assert!(matches!(
    pin!(Or { f1: future::pending::<()>(), f2: future::ready(()) }).poll(&mut context),
    Poll::Ready(Either::R(()))
  ));
  assert!(matches!(
    pin!(Or { f1: future::ready(true), f2: future::ready(false) }).poll(&mut context),
    Poll::Ready(Either::L(true))
  ));
}
