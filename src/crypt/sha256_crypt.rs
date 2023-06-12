pub(crate) const SHA256_SALT_PREFIX: &[u8] = b"$5$";
pub(crate) const SHA256_SALT_PREFIX_STR: &str = "$5$";
pub(super) fn sha256_crypt(key: &[u8], salt: &[u8]) -> Option<String> {
    todo!(
        "SHA256, prefix:{}, key:{}, salt:{}",
        SHA256_SALT_PREFIX_STR,
        String::from_utf8_lossy(key),
        String::from_utf8_lossy(salt)
    )
}
