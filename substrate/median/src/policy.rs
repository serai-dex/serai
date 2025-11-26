/// The policy to use to select the median when the list of candidates is of even length.
pub enum Policy {
  /// When two values are equally considerable, choose the greater value.
  Greater,
  /// When two values are equally considerable, choose the lesser value.
  Lesser,
  /// When two values are equally considerable, choose their average.
  ///
  /// The average will be the sum of the two values divided by two. For how the division may or may
  /// not round, please defer to the `Div` implementation for the value operated over.
  /*
    Internally, this is functionally equivalent to `Policy::Lesser`. It is only when the median is
    finally requested that if the policy is to take the average, we look and see if we need to
    before applying the relevant logic. From the lesser value, finding the complimentary greater
    value is trivial.
  */
  Average,
}

impl Policy {
  /// Calculate the position of the median within the sorted list of values.
  ///
  /// If there are two candidates, `Policy::Greater` and `Policy::Lesser` decide which is chosen,
  /// with `Policy::Average` being interpreted as `Policy::Lesser` _by this function_.
  ///
  /// This will return `0` if the median's list is empty, despite `0` being an invalid position in
  /// that context.
  pub(super) fn target_median_pos(&self, list_length: u64) -> u64 {
    let mut target_median_pos = list_length / 2;
    /*
      If this could be two possible indexes, we use the policy to determine the target index. When
      an odd amount of values are present in the median's list, the integer division by two is
      inherently correct. When there's an even amount of values present, the integer division favors
      the higher value, leading us to correct for when we want the lower value.
    */
    if matches!(self, Policy::Lesser | Policy::Average) && ((list_length % 2) == 0) {
      target_median_pos = target_median_pos.saturating_sub(1);
    }
    target_median_pos
  }
}

#[test]
fn policy() {
  assert_eq!(Policy::Greater.target_median_pos(0), 0);
  assert_eq!(Policy::Greater.target_median_pos(1), 0);
  assert_eq!(Policy::Greater.target_median_pos(2), 1);
  assert_eq!(Policy::Greater.target_median_pos(3), 1);
  assert_eq!(Policy::Greater.target_median_pos(4), 2);

  assert_eq!(Policy::Lesser.target_median_pos(0), 0);
  assert_eq!(Policy::Lesser.target_median_pos(1), 0);
  assert_eq!(Policy::Lesser.target_median_pos(2), 0);
  assert_eq!(Policy::Lesser.target_median_pos(3), 1);
  assert_eq!(Policy::Lesser.target_median_pos(4), 1);

  assert_eq!(Policy::Average.target_median_pos(0), 0);
  assert_eq!(Policy::Average.target_median_pos(1), 0);
  assert_eq!(Policy::Average.target_median_pos(2), 0);
  assert_eq!(Policy::Average.target_median_pos(3), 1);
  assert_eq!(Policy::Average.target_median_pos(4), 1);
}
