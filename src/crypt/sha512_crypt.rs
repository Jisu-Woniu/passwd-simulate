pub(crate) const SHA512_SALT_PREFIX: &[u8] = b"$6$";

pub(super) fn sha512_crypt(key: &[u8], salt: &[u8]) -> Option<String> {
    todo!(
        "key:{}, salt:{}",
        String::from_utf8_lossy(key),
        String::from_utf8_lossy(salt)
    )
}
