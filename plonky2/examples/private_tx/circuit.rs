use anyhow::Result;
use log::Level;

use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::hash::merkle_proofs::{MerkleProof, MerkleProofTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::proof::{Proof, ProofWithPublicInputs};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

pub struct PrivateWitness<F: RichField> {
    pub private_key: [F; 4],
    pub index: usize,
    pub token_id: F,
    pub token_amount: F,
    pub merkle_proof: MerkleProof<F, PoseidonHash>,
}

pub struct PublicInputs<F: RichField> {
    pub(crate) nullifier_value: HashOut<F>,
    pub(crate) new_leaf_value: HashOut<F>,
    pub merkle_root_value: HashOut<F>,
}

pub struct WiringTarget {
    pub merkle_root_target: HashOutTarget,
    pub nulifier_target: HashOutTarget,
    pub new_leaf_target: HashOutTarget,
    pub merkle_proof_target: MerkleProofTarget,
    pub private_key_target: [Target; 4],
    pub token_id_target: Target,
    pub balance_target: Target,
    pub public_key_index_target: Target,
}

/// dont touch this unless there is agreement to do so
pub fn private_tx_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    config: &CircuitConfig,
    tree_height: usize,
) -> (CircuitData<F, C, D>, WiringTarget) {
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    // public data:
    // - merkle root
    let merkle_root_target = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root_target.elements);
    // - nullify
    let nulifier_target = builder.add_virtual_hash();
    builder.register_public_inputs(&nulifier_target.elements);    // - new leaf root
    let new_leaf_target = builder.add_virtual_hash();
    builder.register_public_inputs(&new_leaf_target.elements);
    // - Merkle proof
    let merkle_proof_target = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(tree_height),
    };

    // Prepare the hash data for UTXO tree
    let private_key_target: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
    let token_id_target = builder.add_virtual_target();
    let balance_target = builder.add_virtual_target();
    let public_key_index_target = builder.add_virtual_target();
    let public_key_index_bits_target = builder.split_le(public_key_index_target, tree_height);
    let zero_target = builder.zero();
    let neg_one_target = builder.neg_one();

    builder.verify_merkle_proof::<PoseidonHash>(
        [
            private_key_target,
            [zero_target, zero_target, token_id_target, balance_target],
        ].concat(),
        &public_key_index_bits_target,
        merkle_root_target,
        &merkle_proof_target,
    );


    let old_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [
            private_key_target,
            [zero_target, zero_target, token_id_target, balance_target],
        ].concat(),
    );
    // enforce nullifer == old_leaf
    for i in 0..4 {
        builder.connect(
            nulifier_target.elements[i],
            old_leaf.elements[i],
        );
    }

    //TODO:
    // - enforce nullifier at index = 0
    // - reshash nullifier tree
    // - rehash new leaf
    // - rehash private utxo tree
    (builder.build::<C>(),
     WiringTarget {
         merkle_root_target,
         nulifier_target,
         new_leaf_target,
         merkle_proof_target,
         private_key_target,
         token_id_target,
         balance_target,
         public_key_index_target,
     })
}

pub fn gen_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    data: CircuitData<F, C, D>,
    public_input: PublicInputs<F>,
    witness: PrivateWitness<F>,
    wiring: WiringTarget,
) -> Result<ProofTuple<F, C, D>> {
    let mut pw = PartialWitness::new();

    //public witness
    pw.set_hash_target(wiring.merkle_root_target, public_input.merkle_root_value);
    pw.set_hash_target(wiring.nulifier_target, public_input.nullifier_value);
    pw.set_hash_target(wiring.new_leaf_target, public_input.new_leaf_value);
    for (ht, h) in wiring.merkle_proof_target
        .siblings
        .into_iter()
        .zip(witness.merkle_proof.siblings.clone())
    {
        pw.set_hash_target(ht, h);
    }

    //private witness
    pw.set_target_arr(wiring.private_key_target, witness.private_key);
    pw.set_target(wiring.token_id_target, witness.token_id);
    pw.set_target(wiring.balance_target, witness.token_amount);
    pw.set_target(wiring.public_key_index_target, F::from_canonical_u64(witness.index as u64));


    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();
    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

pub fn verify_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    data: CircuitData<F, C, D>,
    proof: ProofTuple<F, C, D>) -> Result<()> {
    data.verify(proof.0.clone())
}