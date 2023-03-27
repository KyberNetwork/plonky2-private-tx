use anyhow::Result;
use log::Level;

use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::merkle_proofs::{MerkleProof, MerkleProofTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::proof::{Proof, ProofWithPublicInputs};
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
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
    pub nullify_value: HashOut<F>,
    pub merkle_root_value: HashOut<F>,
}

/// dont touch this unless there is agreement to do so
pub fn private_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    config: &CircuitConfig,
    witness: PrivateWitness<F>,
    public_input: PublicInputs<F>,
    tree_height: usize,
) -> Result<ProofTuple<F, C, D>> {
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    //assign virtual public data
    let merkle_root_target = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root_target.elements);

    // TODO: add Nullifier.
    // let nullifier_target = builder.add_virtual_hash();
    // builder.register_public_inputs(&nullifier_target.elements);

    let new_leaf_target = builder.add_virtual_hash();
    builder.register_public_inputs(&new_leaf_target.elements);

    // Merkle proof
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


    let c_t = builder.add_virtual_target().try_into().unwrap();
    builder.register_public_input(c_t);

    builder.add_virtual_target();


    let data = builder.build::<C>();
    let mut pw = PartialWitness::new();

    pw.set_hash_target(merkle_root_target, public_input.merkle_root_value);
    pw.set_target_arr(private_key_target, witness.private_key);

    // pw.set_target(rln_target, rln);
    // pw.set_target(new_rln_target, rln.sub_one());
    // pw.set_target_arr(topic_target, topic);
    // pw.set_target(
    //     public_key_index_target,
    //     F::from_canonical_usize(public_key_index),
    // );
    //
    // for (ht, h) in merkle_proof_target
    //     .siblings
    //     .into_iter()
    //     .zip(merkle_proof.siblings.clone())
    // {
    //     pw.set_hash_target(ht, h);
    // }
    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();
    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

