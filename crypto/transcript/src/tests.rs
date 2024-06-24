use crate::Transcript;

/// Test the sanity of a transcript.
pub fn test_transcript<T: Transcript<Challenge: PartialEq>>() {
  // Ensure distinct names cause distinct challenges
  {
    let mut t1 = T::new(b"1");
    let mut t2 = T::new(b"2");
    assert!(t1.challenge(b"c") != t2.challenge(b"c"));
  }

  // Ensure names can't lead into labels
  {
    let mut t1 = T::new(b"12");
    let c1 = t1.challenge(b"c");
    let mut t2 = T::new(b"1");
    let c2 = t2.challenge(b"2c");
    assert!(c1 != c2);
  }

  let t = || T::new(b"name");
  let c = |mut t: T| t.challenge(b"c");

  // Ensure domain separators do something
  {
    let mut t1 = t();
    t1.domain_separate(b"d");
    assert!(c(t1) != c(t()));
  }

  // Ensure distinct domain separators create distinct challenges
  {
    let mut t1 = t();
    let mut t2 = t();
    t1.domain_separate(b"d1");
    t2.domain_separate(b"d2");
    assert!(c(t1) != c(t2));
  }

  // Ensure distinct messages create distinct challenges
  {
    // By label
    {
      let mut t1 = t();
      let mut t2 = t();
      t1.append_message(b"msg", b"a");
      t2.append_message(b"msg", b"b");
      assert!(c(t1) != c(t2));
    }

    // By value
    {
      let mut t1 = t();
      let mut t2 = t();
      t1.append_message(b"a", b"val");
      t2.append_message(b"b", b"val");
      assert!(c(t1) != c(t2));
    }
  }

  // Ensure challenges advance the transcript
  {
    let mut t = t();
    let c1 = t.challenge(b"c");
    let c2 = t.challenge(b"c");
    assert!(c1 != c2);
  }

  // Ensure distinct challenge labels produce distinct challenges
  assert!(t().challenge(b"a") != t().challenge(b"b"));

  // Ensure RNG seed calls advance the transcript
  {
    let mut t = t();
    let s1 = t.rng_seed(b"s");
    let s2 = t.rng_seed(b"s");
    assert!(s1 != s2);
  }

  // Ensure distinct RNG seed labels produce distinct seeds
  assert!(t().rng_seed(b"a") != t().rng_seed(b"b"));
}

#[test]
fn test_digest() {
  test_transcript::<crate::DigestTranscript<sha2::Sha256>>();
  test_transcript::<crate::DigestTranscript<blake2::Blake2b512>>();
}

#[cfg(feature = "recommended")]
#[test]
fn test_recommended() {
  test_transcript::<crate::RecommendedTranscript>();
}

#[cfg(feature = "merlin")]
#[test]
fn test_merlin() {
  test_transcript::<crate::MerlinTranscript>();
}
