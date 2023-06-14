use anyhow::{Error, Result};

use self::{
    md5_crypt::{md5_crypt, MD5_SETTING_PREFIX},
    sha256_crypt::{sha256_crypt, SHA256_SALT_PREFIX},
    sha512_crypt::{sha512_crypt, SHA512_SALT_PREFIX},
};

mod md5_crypt;
pub(super) mod salt;
mod sha256_crypt;
mod sha512_crypt;

const BINARY64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn is_safe(&c: &u8) -> bool {
    c != b'$' && c != b':' && c != b'\n'
}

fn to64(mut u: u32, mut n: i32) -> Vec<u8> {
    let mut s = Vec::new();
    while n > 0 {
        n -= 1;
        s.push(BINARY64[(u as usize) % 64]);
        u /= 64;
    }
    s
}

pub fn crypt(key: &[u8], salt: &[u8]) -> Result<String> {
    if salt.starts_with(MD5_SETTING_PREFIX) {
        md5_crypt(key, salt)
    } else if salt.starts_with(SHA256_SALT_PREFIX) {
        sha256_crypt(key, salt) //.ok_or_else(|| Error::msg("Failed to generate SHA256 hash"))
    } else if salt.starts_with(SHA512_SALT_PREFIX) {
        sha512_crypt(key, salt)
    } else {
        // des_crypt(key, salt)
        Err(Error::msg(
            "DES is no longer supported, use a modern hash instead.",
        ))
    }
}

fn permute(md: &[u8], output: &mut Vec<u8>, perm: &[[usize; 3]]) {
    for p in perm {
        output.extend(&to64(
            ((md[p[0]] as u32) << 16) | ((md[p[1]] as u32) << 8) | (md[p[2]] as u32),
            4,
        ))
    }
}
