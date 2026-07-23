use core::{
  pin::Pin,
  task::{Poll, Context},
  future::Future,
  time::Duration,
};

use crate::{Either, Or};

/// A provider for the functionality to sleep.
pub(crate) trait Sleep {
  /// An asynchronous implementation of [`std::thread::sleep`].
  ///
  /// This MUST be cancel-safe.
  fn sleep(duration: Duration) -> impl Future<Output = ()>;
}

// TODO: Should `Sleep` be promoted into the public API to avoid this?
mod sleep_for_network {
  use core::marker::PhantomData;
  use crate::{Validator, Signature, AggregateSignature, Block, Network};
  use super::*;

  #[repr(transparent)]
  pub(crate) struct SleepForNetwork<
    V: Validator,
    S: Signature,
    A: AggregateSignature,
    B: Block,
    N: Network<V, S, A, B>,
  >(PhantomData<(V, S, A, B, N)>);

  impl<V: Validator, S: Signature, A: AggregateSignature, B: Block, N: Network<V, S, A, B>> Sleep
    for SleepForNetwork<V, S, A, B, N>
  {
    fn sleep(duration: Duration) -> impl Future<Output = ()> {
      <N as Network<V, S, A, B>>::sleep(duration)
    }
  }
}
pub(crate) use sleep_for_network::SleepForNetwork;

/// The timeout expired.
pub(crate) struct TimeoutExpired;

pin_project_lite::pin_project! {
  /// A timeout.
  ///
  /// Internally, this is constructed as the [`Or`] composition of the specified future with the
  /// future output by [`Sleep::sleep`]. This is cancel-safe.
  struct Timeout<F, S> {
    #[pin] or: Or<F, S>,
  }
}

impl<F: Future, S: Future<Output = ()>> Future for Timeout<F, S> {
  type Output = Result<F::Output, TimeoutExpired>;
  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    match self.as_mut().project().or.poll(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Either::L(value)) => Poll::Ready(Ok(value)),
      Poll::Ready(Either::R(())) => Poll::Ready(Err(TimeoutExpired)),
    }
  }
}

/// Await completion of the future only for at most approximately `duration`.
///
/// Even if the duration has already passed, this will favor the future and check if it is ready
/// before checking if the duration has expired. This may cause it to poll the future once more
/// after the duration has already expired, hence "at most approximately" and not just "at most".
///
/// `future` MUST be cancel-safe. The future this returns will be cancel-safe.
pub(crate) fn timeout<S: Sleep, F: Future>(
  future: F,
  duration: Duration,
) -> impl Future<Output = Result<F::Output, TimeoutExpired>> {
  Timeout { or: Or { f1: future, f2: S::sleep(duration) } }
}

#[cfg(test)]
#[tokio::test]
async fn test_timeout() {
  use core::future;

  struct TokioSleep;
  impl Sleep for TokioSleep {
    fn sleep(duration: Duration) -> impl Future<Output = ()> {
      tokio::time::sleep(duration)
    }
  }

  assert!(matches!(timeout::<TokioSleep, _>(future::ready(()), Duration::ZERO).await, Ok(())));
  assert!(matches!(
    timeout::<TokioSleep, _>(future::pending::<()>(), Duration::ZERO).await,
    Err(TimeoutExpired)
  ));

  {
    #[cfg(feature = "std")]
    let now = std::time::Instant::now();
    let duration = Duration::from_millis(100);
    assert!(matches!(
      timeout::<TokioSleep, _>(tokio::time::sleep(duration), Duration::from_millis(200)).await,
      Ok(())
    ));
    #[cfg(feature = "std")]
    assert!(now.elapsed() >= duration);
  }

  {
    #[cfg(feature = "std")]
    let now = std::time::Instant::now();
    let duration = Duration::from_millis(100);
    assert!(matches!(
      timeout::<TokioSleep, _>(tokio::time::sleep(10 * duration), duration).await,
      Err(TimeoutExpired)
    ));
    #[cfg(feature = "std")]
    assert!(now.elapsed() >= duration);
  }
}
