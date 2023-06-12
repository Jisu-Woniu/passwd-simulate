use super::BINARY64;
use std::iter::from_fn;

use rand::seq::SliceRandom;

pub(crate) fn make_salt(n: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    from_fn(|| BINARY64.choose(&mut rng).cloned())
        .take(n)
        .collect()
}
