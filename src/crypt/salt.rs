use std::iter::from_fn;

use rand::{seq::SliceRandom, CryptoRng, RngCore};

use super::BINARY64;

pub fn make_salt<R>(n: usize, mut rng: R) -> Vec<u8>
where
    R: CryptoRng + RngCore,
{
    from_fn(|| BINARY64.choose(&mut rng).cloned())
        .take(n)
        .collect()
}
