pub(crate) const BCRYPT_SALT_PREFIX: &[u8] = b"$2$";

pub(super) fn bcrypt_crypt(key: &[u8], salt: &[u8]) -> Option<String> {
    todo!(
        "key:{}, salt:{}",
        String::from_utf8_lossy(key),
        String::from_utf8_lossy(salt)
    )
}
