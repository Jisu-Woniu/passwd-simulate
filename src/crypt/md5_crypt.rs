use md5::{Digest, Md5};

pub(crate) const MD5_SALT_PREFIX: &[u8; 3] = b"$1$";
pub(crate) const MD5_SALT_PREFIX_STR: &str = "$1$";

const KEY_MAX_LEN: usize = 30000;

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
        .chain_update(MD5_SALT_PREFIX)
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
    for perm in PERM {
        output.extend(&to64(
            ((md[perm[0]] as u32) << 16) | ((md[perm[1]] as u32) << 8) | (md[perm[2]] as u32),
            4,
        ))
    }
    output.extend(&to64(md[11] as u32, 2));
    String::from_utf8(output).ok()
}

use super::BINARY64;

fn to64(mut u: u32, mut n: i32) -> Vec<u8> {
    let mut s = Vec::new();
    while n > 0 {
        n -= 1;
        s.push(BINARY64[(u as usize) % 64]);
        u /= 64;
    }
    s
}

pub(super) fn md5_crypt(key: &[u8], setting: &[u8]) -> Option<String> {
    let key_len = key.len();
    // Reject large keys
    if key_len > KEY_MAX_LEN {
        return None;
    }
    // setting: $1$salt$ (closing $ is optional)

    if !setting.starts_with(MD5_SALT_PREFIX) {
        return None;
    }

    let mut salt_clean = &setting[MD5_SALT_PREFIX.len()..];

    salt_clean = salt_clean.splitn(2, |&c| c == b'$').next()?;

    if !salt_clean.iter().all(|&c| is_safe(c)) {
        return None;
    }
    Some(format!(
        "{}{}${}",
        MD5_SALT_PREFIX_STR,
        String::from_utf8_lossy(&salt_clean),
        md5_crypt_clean(key, &salt_clean)?
    ))
}

fn is_safe(c: u8) -> bool {
    c != b'$' && c != b':' && c != b'\n'
}

mod tests {
    #[test]
    fn update() {
        use md5::{Digest, Md5};

        let mut ctx = Md5::new();
        ctx.update(&[1][..]);
        ctx.update(&[2][..]);
        let result1 = ctx.finalize();

        let result2 = Md5::new()
            .chain_update(&[1][..])
            .chain_update(&[2][..])
            .finalize();

        let mut ctx = Md5::new();
        ctx.update(&[1, 2][..]);
        let result3 = ctx.finalize();

        assert_eq!(result1, result2);
        assert_eq!(result1, result3);
    }

    #[test]
    fn crypt() {
        use super::md5_crypt;

        let test_key = b"Xy01@#!";
        let test_setting = b"$1$abcd0123$";
        let test_hash = "$1$abcd0123$qFLW2hU/ia/dRaRxSn1E11";
        let result = md5_crypt(test_key, test_setting);
        assert_eq!(Some(test_hash.to_string()), result);
    }
}
