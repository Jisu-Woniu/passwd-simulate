use std::{num::IntErrorKind::PosOverflow, str::from_utf8};

use anyhow::{Error, Result};
use digest::Output;
use sha2::{Digest, Sha256};

use crate::crypt::{is_safe, permute, to64};

pub(crate) const SHA256_SALT_PREFIX: &[u8; 3] = b"$5$";
const KEY_MAX_LEN: usize = 256;
const ROUNDS_MIN: usize = 1000;
const ROUNDS_MAX: usize = 9999999;
const SALT_MAX: usize = 16;

pub(super) fn sha256_crypt(key: &[u8], setting: &[u8]) -> Result<String> {
    let key_len = key.len();
    // Reject large keys
    if key_len > KEY_MAX_LEN {
        Err(Error::msg("Key is too long"))?;
    }

    // setting: $5$rounds=n$salt$ (rounds=n$ and closing $ are optional)
    if !setting.starts_with(SHA256_SALT_PREFIX) {
        Err(Error::msg("Wrong prefix"))?;
    }
    let mut settings = setting[SHA256_SALT_PREFIX.len()..].splitn(3, |&c| c == b'$');
    const ROUNDS_PREFIX: &[u8; 7] = b"rounds=";
    let rounds_or_salt = settings.next().ok_or_else(|| Error::msg("Salt missing"))?;
    let mut rounds: usize = 5000;
    let salt;

    let has_rounds = rounds_or_salt.starts_with(ROUNDS_PREFIX);
    if has_rounds {
        // Bad rounds setting is rejected if it is
        // - empty
        // - unterminated (missing '$')
        // - begins with anything but a decimal digit
        // all these can be handled by `parse`.
        // Since salt cannot contain a '=', we return `None` immediately when the parse failed.

        rounds = (match from_utf8(&rounds_or_salt[ROUNDS_PREFIX.len()..])?.parse::<usize>() {
            Ok(r) => Ok(r),
            Err(e) => match e.kind() {
                PosOverflow => Err(Error::msg("Too many rounds"))?,
                _ => Err(e),
            },
        })?;

        if rounds < ROUNDS_MIN {
            rounds = ROUNDS_MIN;
        } else if rounds > ROUNDS_MAX {
            Err(Error::msg("Too many rounds"))?;
        }

        salt = settings.next().ok_or_else(|| Error::msg("Salt missing"))?;
    } else {
        salt = rounds_or_salt;
    }

    let salt = if salt.len() > SALT_MAX {
        &salt[..SALT_MAX]
    } else if salt.is_empty() {
        Err(Error::msg("Salt missing"))?
    } else {
        salt
    };

    if !salt.iter().all(is_safe) {
        Err(Error::msg("Unsafe character found in salt"))?
    }

    let setting_clean = setting
        .splitn(5, |&c| c == b'$')
        .take(if has_rounds { 4 } else { 3 })
        .skip(1)
        .map(|s| from_utf8(s).unwrap())
        .fold(String::new(), |mut r, s| {
            r += "$";
            r += s;
            r
        });

    Ok(format!(
        "{}${}",
        setting_clean,
        sha256_crypt_clean(key, salt, rounds)
            .ok_or_else(|| Error::msg("Failed generating SHA256 hash"))?
    ))
}

fn sha256_crypt_clean(key: &[u8], salt: &[u8], rounds: usize) -> Option<String> {
    // B = sha(key salt key)
    let md = Sha256::new()
        .chain_update(key)
        .chain_update(salt)
        .chain_update(key)
        .finalize();

    // A = sha(key salt repeat-B alternate-B-key)
    let mut ctx = Sha256::new().chain_update(key).chain_update(salt);
    let key_len = key.len();
    hashmd(&mut ctx, key_len, md);
    let mut i = key_len;
    while i > 0 {
        if i % 2 != 0 {
            ctx.update(md);
        } else {
            ctx.update(key);
        }
        i >>= 1;
    }
    let mut md = ctx.finalize();

    // DP = sha(repeat-key), this step takes O(klen^2) time
    let mut ctx = Sha256::new();
    for _ in 0..key_len {
        ctx.update(key);
    }
    let kmd = ctx.finalize();

    // DS = sha(repeat-salt)
    let mut ctx = Sha256::new();
    for _ in 0..(16 + md[0]) {
        ctx.update(salt);
    }
    let smd = ctx.finalize();

    let salt_len = salt.len();

    // iterate A = f(A,DP,DS), this step takes O(rounds*klen) time
    for i in 0..rounds {
        let mut ctx = Sha256::new();
        if i % 2 != 0 {
            hashmd(&mut ctx, key_len, kmd);
        } else {
            ctx.update(md);
        }
        if i % 3 != 0 {
            ctx.update(&smd[..salt_len]);
        }
        if i % 7 != 0 {
            hashmd(&mut ctx, key_len, kmd);
        }
        if i % 2 != 0 {
            ctx.update(md);
        } else {
            hashmd(&mut ctx, key_len, kmd);
        }
        md = ctx.finalize();
    }
    const PERM: [[usize; 3]; 10] = [
        [0, 10, 20],
        [21, 1, 11],
        [12, 22, 2],
        [3, 13, 23],
        [24, 4, 14],
        [15, 25, 5],
        [6, 16, 26],
        [27, 7, 17],
        [18, 28, 8],
        [9, 19, 29],
    ];
    let mut output = Vec::new();

    permute(&md, &mut output, &PERM);
    output.extend(&to64(((md[31] as u32) << 8) | (md[30] as u32), 3));
    String::from_utf8(output).ok()
}

fn hashmd(s: &mut Sha256, n: usize, md: Output<Sha256>) {
    let mut i = n;
    while i > 32 {
        s.update(&md[..32]);
        i -= 32;
    }
    s.update(&md[..i]);
}

#[cfg(test)]
pub mod tests {
    use crate::crypt::sha256_crypt::sha256_crypt;

    #[test]
    fn hash_test() -> anyhow::Result<()> {
        use super::sha256_crypt;
        let key = b"Xy01@#!";
        let setting = b"$5$rounds=1234$abc0123456789$";
        let expected =
            "$5$rounds=1234$abc0123456789$.AApOy/ZKLFQjpW80rPbRI7TD/mXALa4V3ASyXr8FG7".to_string();
        let output = sha256_crypt(key, setting)?;
        let verify_output = sha256_crypt(key, expected.as_bytes())?;

        assert_eq!(output, expected);
        assert_eq!(verify_output, expected);
        Ok(())
    }

    #[test]
    fn no_salt_error() {
        let output = sha256_crypt(b"Xy01@#!", b"$5$rounds=1234$");
        assert!(output.is_err());
    }
}
