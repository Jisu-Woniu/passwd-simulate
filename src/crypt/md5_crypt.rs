use std::str::from_utf8;

use anyhow::{Error, Result};
use md5::{Digest, Md5};

use super::{is_safe, to64};

pub(crate) const MD5_SETTING_PREFIX: &[u8; 3] = b"$1$";
pub(crate) const MD5_SETTING_PREFIX_STR: &str = "$1$";

const KEY_MAX_LEN: usize = 30000;

/// Crypt core algorithm.
fn md5_crypt_clean(key: &[u8], salt: &[u8]) -> Option<String> {
    // md5(key salt key)
    let mut md = Md5::new()
        .chain_update(key)
        .chain_update(salt)
        .chain_update(key)
        .finalize();

    // md5(key $1$ salt repeated-md weird-key[0]-0)
    let mut ctx = Md5::new()
        .chain_update(key)
        .chain_update(MD5_SETTING_PREFIX)
        .chain_update(salt);

    let key_len = key.len();
    let mut i = key_len;

    let output_size = Md5::output_size();
    while i > output_size {
        ctx.update(md);
        i -= output_size;
    }

    ctx.update(&md[..i]);
    md[0] = 0;
    let mut i = key_len;
    while i != 0 {
        if (i & 1) != 0 {
            ctx.update(&md[..1]);
        } else {
            ctx.update(&key[..1])
        }
        i >>= 1;
    }
    let mut md = ctx.finalize();

    // md = f(md, key, salt) iteration

    for i in 0..1000 {
        let mut ctx = Md5::new();
        if i % 2 != 0 {
            ctx.update(key);
        } else {
            ctx.update(md);
        }
        if i % 3 != 0 {
            ctx.update(salt);
        }
        if i % 7 != 0 {
            ctx.update(key);
        }
        if i % 2 != 0 {
            ctx.update(md);
        } else {
            ctx.update(key);
        }
        md = ctx.finalize();
    }

    const PERM: [[usize; 3]; 5] = [[0, 6, 12], [1, 7, 13], [2, 8, 14], [3, 9, 15], [4, 10, 5]];
    let mut output = Vec::new();

    for p in &PERM {
        output.extend(&to64(
            ((md[p[0]] as u32) << 16) | ((md[p[1]] as u32) << 8) | (md[p[2]] as u32),
            4,
        ))
    }

    output.extend(&to64(md[11] as u32, 2));
    String::from_utf8(output).ok()
}

/// Wrapper, boundary situations management.
pub(super) fn md5_crypt(key: &[u8], setting: &[u8]) -> Result<String> {
    let key_len = key.len();

    // Reject large keys
    if key_len > KEY_MAX_LEN {
        Err(Error::msg("Key too long"))?;
    }

    // setting: $1$salt$ (closing $ is optional)
    if !setting.starts_with(MD5_SETTING_PREFIX) {
        Err(Error::msg("Wrong prefix"))?;
    }

    // Extract salt
    let salt = setting[MD5_SETTING_PREFIX.len()..]
        .splitn(2, |&c| c == b'$')
        .next()
        .ok_or_else(|| Error::msg("Salt missing"))?;
    const SALT_MAX: usize = 8;
    let salt = if salt.len() > SALT_MAX {
        &salt[..SALT_MAX]
    } else {
        salt
    };
    if !salt.iter().all(is_safe) {
        Err(Error::msg("Unsafe character found in salt"))?;
    }
    Ok(format!(
        "{}{}${}",
        MD5_SETTING_PREFIX_STR,
        from_utf8(salt)?,
        md5_crypt_clean(key, salt).ok_or_else(|| Error::msg("Failed generating MD5 hash"))?
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn crypt() -> anyhow::Result<()> {
        use super::md5_crypt;

        let test_key = b"Xy01@#!";
        let test_setting = b"$1$abcd0123$";
        let test_hash = "$1$abcd0123$qFLW2hU/ia/dRaRxSn1E11";
        let result = md5_crypt(test_key, test_setting)?;
        assert_eq!(test_hash.to_string(), result);
        Ok(())
    }
}
