use crate::{Digest, PlonkyProof, C, F};

use plonky2::field::types::Field;
use plonky2::field::types::Sample;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

pub struct Voter {
    pub sk: Digest,
    pub pk: Digest,
}

impl Voter {
    pub fn new() -> Self {
        let sk: Digest = F::rand_array();
        let pk: Digest = PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat()).elements;
        Self { sk, pk }
    }
}
