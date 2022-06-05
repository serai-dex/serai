use crate::curves::expand_message_xmd_sha256;

#[test]
fn test_xmd_sha256() {
  assert_eq!(
    hex::encode(expand_message_xmd_sha256(b"QUUX-V01-CS02-with-expander", b"", 0x80).unwrap()),
    (
      "8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f8".to_owned() +
      "9580d217aa79526f1708354a76a402d3569d6a9d19ef3de4d0b991" +
      "e4f54b9f20dcde9b95a66824cbdf6c1a963a1913d43fd7ac443a02" +
      "fc5d9d8d77e2071b86ab114a9f34150954a7531da568a1ea8c7608" +
      "61c0cde2005afc2c114042ee7b5848f5303f0611cf297f"
    )
  );
}
