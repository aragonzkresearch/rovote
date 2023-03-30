use crate::innerproof::*;
use crate::{Digest, PlonkyProof, C, F};

use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::proof::ProofWithPublicInputs;

impl CensusTree {
    pub fn aggregate_proofs(
        chain_id: usize,
        process_id: usize,
        census_root: Digest,
        proof0: ProofPackage,
        proof1: ProofPackage,
        verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> (Digest, Digest, PlonkyProof) {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        let public_inputs0: Vec<F> = vec![F::from_canonical_usize(chain_id)]
            .into_iter()
            .chain(vec![F::from_canonical_usize(process_id)].into_iter())
            .chain(census_root)
            .chain(proof0.nullifier)
            .collect();
        let public_inputs1: Vec<F> = vec![F::from_canonical_usize(chain_id)]
            .into_iter()
            .chain(vec![F::from_canonical_usize(process_id)].into_iter())
            .chain(census_root)
            .chain(proof1.nullifier)
            .collect();

        let proof_target0 = builder.add_virtual_proof_with_pis(&verifier_data.common);
        pw.set_proof_with_pis_target(
            &proof_target0,
            &ProofWithPublicInputs {
                proof: proof0.proof,
                public_inputs: public_inputs0,
            },
        );
        let proof_target1 = builder.add_virtual_proof_with_pis(&verifier_data.common);
        pw.set_proof_with_pis_target(
            &proof_target1,
            &ProofWithPublicInputs {
                proof: proof1.proof,
                public_inputs: public_inputs1,
            },
        );

        let vd_target =
            builder.add_virtual_verifier_data(verifier_data.common.fri_params.config.cap_height);
        pw.set_verifier_data_target(&vd_target, &verifier_data.verifier_only);

        pw.set_cap_target(
            &vd_target.constants_sigmas_cap,
            &verifier_data.verifier_only.constants_sigmas_cap,
        );

        builder.verify_proof::<C>(&proof_target0, &vd_target, &verifier_data.common);
        builder.verify_proof::<C>(&proof_target1, &vd_target, &verifier_data.common);

        let data = builder.build();
        let recursive_proof = data.prove(pw).unwrap();

        data.verify(recursive_proof.clone()).unwrap();

        (proof0.nullifier, proof1.nullifier, recursive_proof.proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::voter::Voter;

    #[test]
    fn test_aggregate_2_innerproofs() {
        let chain_id = 42;
        let process_id = 3;
        let n = 256;
        let voters: Vec<Voter> = (0..n).map(|_| Voter::new()).collect();

        let pks: Vec<Vec<F>> = voters.iter().map(|v| v.pk.to_vec()).collect();
        let census_tree = CensusTree::new(pks);

        let census_root = census_tree.root();

        let i = 84;
        let (proof0, vd) = census_tree
            .gen_proof(chain_id, process_id, voters[i].sk, i)
            .unwrap();

        let i = 101;
        let (proof1, vd) = census_tree
            .gen_proof(chain_id, process_id, voters[i].sk, i)
            .unwrap();

        let (n0, n1, proof) =
            CensusTree::aggregate_proofs(chain_id, process_id, census_root, proof0, proof1, &vd);
    }
}
