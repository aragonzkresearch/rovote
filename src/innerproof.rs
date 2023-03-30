use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOutTarget, MerkleCapTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::{Digest, PlonkyProof, C, F};

pub struct CensusTargets {
    chain_id: Target,
    process_id: Target,
    census_root: HashOutTarget,
    merkle_proof: MerkleProofTarget,
    sk: [Target; 4],
    pk_i: Target,
}

pub struct CensusTree(pub MerkleTree<F, PoseidonHash>);

#[derive(Debug, Clone)]
pub struct ProofPackage {
    pub nullifier: Digest,
    pub proof: PlonkyProof,
}

impl CensusTree {
    pub fn tree_height(&self) -> usize {
        self.0.leaves.len().trailing_zeros() as usize
    }
    pub fn root(&self) -> Digest {
        self.0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .collect::<Vec<F>>()
            .try_into()
            .unwrap()
    }

    pub fn circuit(&self, builder: &mut CircuitBuilder<F, 2>) -> CensusTargets {
        // Register public inputs.
        let chain_id: Target = builder.add_virtual_target().try_into().unwrap();
        builder.register_public_input(chain_id);
        let process_id: Target = builder.add_virtual_target().try_into().unwrap();
        builder.register_public_input(process_id);
        let census_root = builder.add_virtual_hash();
        builder.register_public_inputs(&census_root.elements);
        let nullifier = builder.add_virtual_hash();
        builder.register_public_inputs(&nullifier.elements);

        // Merkle proof
        let merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(self.tree_height()),
        };

        // Verify public key Merkle proof.
        let sk: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        let pk_i = builder.add_virtual_target();
        let pk_i_bits = builder.split_le(pk_i, self.tree_height());
        let zero = builder.zero();
        builder.verify_merkle_proof::<PoseidonHash>(
            [sk, [zero; 4]].concat(),
            &pk_i_bits,
            census_root,
            &merkle_proof,
        );

        // Check nullifier.
        let zero = builder.zero();
        let should_be_nullifier = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            [sk, [chain_id, process_id, zero, zero]].concat(),
        );
        for i in 0..4 {
            builder.connect(nullifier.elements[i], should_be_nullifier.elements[i]);
        }

        CensusTargets {
            chain_id,
            process_id,
            census_root,
            merkle_proof,
            sk,
            pk_i,
        }
    }
    pub fn fill_census_targets(
        &self,
        pw: &mut PartialWitness<F>,
        chain_id: usize,
        process_id: usize,
        sk: Digest,
        pk_i: usize,
        targets: CensusTargets,
    ) {
        let CensusTargets {
            chain_id: chain_id_target,
            process_id: process_id_target,
            census_root,
            merkle_proof: merkle_proof_target,
            sk: sk_target,
            pk_i: pk_i_target,
        } = targets;

        pw.set_target(chain_id_target, F::from_canonical_usize(chain_id));
        pw.set_target(process_id_target, F::from_canonical_usize(process_id));
        pw.set_hash_target(census_root, self.0.cap.0[0]);
        pw.set_target_arr(sk_target, sk);
        pw.set_target(pk_i_target, F::from_canonical_usize(pk_i));

        let merkle_proof = self.0.prove(pk_i);
        for (ht, h) in merkle_proof_target
            .siblings
            .into_iter()
            .zip(merkle_proof.siblings)
        {
            pw.set_hash_target(ht, h);
        }
    }
}

// proof related
impl CensusTree {
    pub fn gen_proof(
        &self,
        chain_id: usize,
        process_id: usize,
        sk: Digest,
        pk_i: usize,
    ) -> Result<(ProofPackage, VerifierCircuitData<F, C, 2>)> {
        let nullifier = PoseidonHash::hash_no_pad(
            &[
                sk,
                [
                    F::from_canonical_usize(chain_id),
                    F::from_canonical_usize(process_id),
                    F::ZERO,
                    F::ZERO,
                ],
            ]
            .concat(),
        )
        .elements;
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        let targets = self.circuit(&mut builder);
        self.fill_census_targets(&mut pw, chain_id, process_id, sk, pk_i, targets);

        let data = builder.build();
        let proof = data.prove(pw)?;

        Ok((
            ProofPackage {
                nullifier,
                proof: proof.proof,
            },
            data.verifier_data(),
        ))
    }

    pub fn verify_proof(
        &self,
        chain_id: usize,
        process_id: usize,
        census_root: Digest,
        proof: ProofPackage,
        verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> Result<()> {
        let public_inputs: Vec<F> = vec![F::from_canonical_usize(chain_id)]
            .into_iter()
            .chain(vec![F::from_canonical_usize(process_id)].into_iter())
            .chain(census_root)
            .chain(proof.nullifier)
            .collect();

        verifier_data.verify(ProofWithPublicInputs {
            proof: proof.proof,
            public_inputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::innerproof::{Digest, F};
    use plonky2::field::types::{Field, Sample};

    #[test]
    fn test_inner_proof() {
        let chain_id = 42;
        let process_id = 3;
        let n = 256;
        let sks: Vec<Digest> = (0..n).map(|_| F::rand_array()).collect();
        let pks: Vec<Vec<F>> = sks
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();

        let census_tree = CensusTree(MerkleTree::new(pks, 0));

        let census_root = census_tree.root();

        let i = 84;

        let (proof, vd) = census_tree
            .gen_proof(chain_id, process_id, sks[i], i)
            .unwrap();
        census_tree
            .verify_proof(chain_id, process_id, census_root, proof, &vd)
            .unwrap();
    }
}
