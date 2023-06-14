use std::{num::IntErrorKind::PosOverflow, str::from_utf8};

use anyhow::{Error, Result};
use digest::Output;
use sha2::{Digest, Sha512};

use super::{is_safe, to64};

pub(crate) const SHA512_SALT_PREFIX: &[u8; 3] = b"$6$";
const KEY_MAX_LEN: usize = 256;
const ROUNDS_MIN: usize = 1000;
const ROUNDS_MAX: usize = 9999999;
const SALT_MAX: usize = 16;

pub(super) fn sha512_crypt(key: &[u8], setting: &[u8]) -> Result<String> {
    let key_len = key.len();
    // Reject large keys
    if key_len > KEY_MAX_LEN {
        Err(Error::msg("Key is too long"))?;
    }

    // setting: $6$rounds=n$salt$ (rounds=n$ and closing $ are optional)
    if !setting.starts_with(SHA512_SALT_PREFIX) {
        Err(Error::msg("Wrong prefix"))?;
    }
    let mut settings = setting[SHA512_SALT_PREFIX.len()..].splitn(3, |&c| c == b'$');
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
        sha512_crypt_clean(key, salt, rounds)
            .ok_or_else(|| Error::msg("Failed generating SHA512 hash"))?
    ))
}

fn sha512_crypt_clean(key: &[u8], salt: &[u8], rounds: usize) -> Option<String> {
    // B = sha(key salt key)
    let md = Sha512::new()
        .chain_update(key)
        .chain_update(salt)
        .chain_update(key)
        .finalize();

    // A = sha(key salt repeat-B alternate-B-key)
    let mut ctx = Sha512::new().chain_update(key).chain_update(salt);
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
    let mut ctx = Sha512::new();
    for _ in 0..key_len {
        ctx.update(key);
    }
    let kmd = ctx.finalize();

    // DS = sha(repeat-salt)
    let mut ctx = Sha512::new();
    for _ in 0..(16 + md[0]) {
        ctx.update(salt);
    }
    let smd = ctx.finalize();

    let salt_len = salt.len();

    // iterate A = f(A,DP,DS), this step takes O(rounds*klen) time
    for i in 0..rounds {
        let mut ctx = Sha512::new();
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
    const PERM: [[usize; 3]; 21] = [
        [0, 21, 42],
        [22, 43, 1],
        [44, 2, 23],
        [3, 24, 45],
        [25, 46, 4],
        [47, 5, 26],
        [6, 27, 48],
        [28, 49, 7],
        [50, 8, 29],
        [9, 30, 51],
        [31, 52, 10],
        [53, 11, 32],
        [12, 33, 54],
        [34, 55, 13],
        [56, 14, 35],
        [15, 36, 57],
        [37, 58, 16],
        [59, 17, 38],
        [18, 39, 60],
        [40, 61, 19],
        [62, 20, 41],
    ];
    let mut output = Vec::new();

    {
        for p in &PERM {
            output.extend(&to64(
                ((md[p[0]] as u32) << 16) | ((md[p[1]] as u32) << 8) | (md[p[2]] as u32),
                4,
            ))
        }
    };
    output.extend(&to64(md[63] as u32, 2));
    String::from_utf8(output).ok()
}

fn hashmd(s: &mut Sha512, n: usize, md: Output<Sha512>) {
    let mut i = n;
    while i > 64 {
        s.update(&md[..64]);
        i -= 64;
    }
    s.update(&md[..i]);
}

#[cfg(test)]
pub mod tests {
    use crate::crypt::sha512_crypt::sha512_crypt;

    #[test]
    fn hash_test() -> anyhow::Result<()> {
        use super::sha512_crypt;
        let key = b"Xy01@#!";
        let setting = b"$6$rounds=1234$abc0123456789$";
        let expected = "$6$rounds=1234$abc0123456789$GW2GqS6IFl0mQA26RRt3pDnqhQzym4B0Ly7wVLuJZKFmPpOKX4j5zH6Rh4NqdGIf9Kqxcz4KltEh8tXjI.Zec.".to_string();
        let output = sha512_crypt(key, setting)?;
        let verify_output = sha512_crypt(key, expected.as_bytes())?;
        assert_eq!(output, expected);
        assert_eq!(verify_output, expected);
        Ok(())
    }

    #[test]
    fn no_salt_error() {
        let output = sha512_crypt(b"Xy01@#!", b"$6$rounds=1234$");
        assert!(output.is_err());
    }
}
