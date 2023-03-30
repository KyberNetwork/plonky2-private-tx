mod bench_recursion_fork;
mod circuit;
mod client_emulation;
mod server_emulation;
mod state;
mod utxo;

use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use log::info;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs};
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::{Field, Sample};

use crate::bench_recursion_fork::{
    generate_circom_verifier, generate_proof_base64, generate_verifier_config, test_serialization,
};
use crate::circuit::{
    gen_private_proof, private_tx_circuit, verify_proof, PrivateWitness, PublicInputs,
};
use crate::client_emulation::Client;
use crate::server_emulation::Server;
use crate::state::State;

fn main() {
    env_logger::init();

    info!("starting test");
    const D: usize = 2;
    const tree_height: usize = 10;
    let zk_config = CircuitConfig::standard_recursion_config();
    let (data, wr) =
        private_tx_circuit::<GoldilocksField, PoseidonGoldilocksConfig, D>(&zk_config, tree_height);
    let token_id = GoldilocksField::from_canonical_u64(1);
    let balance: u64 = 1000;
    let delta: u64 = 100;
    let priv_key: [GoldilocksField; 4] = GoldilocksField::rand_array();
    let (demo, index) = State::new_demo_state(priv_key, token_id, balance, 10);
    let merkle_proof = demo.private_utxo_tree.prove(index);

    let old_private_tree_hash = PoseidonHash::hash_no_pad(
        &[
            priv_key,
            [
                GoldilocksField::ZERO,
                GoldilocksField::ZERO,
                token_id,
                GoldilocksField::from_canonical_u64(balance),
            ],
        ]
        .concat(),
    );
    // info!("old private hash {:?}", old_private_tree_hash);
    let old_root = demo.private_utxo_tree.cap.0[0];
    let new_private_tree_hash = PoseidonHash::hash_no_pad(
        &[
            priv_key,
            [
                GoldilocksField::ZERO,
                GoldilocksField::ZERO,
                token_id,
                GoldilocksField::from_canonical_u64(balance - delta),
            ],
        ]
        .concat(),
    );
    let pub_input = PublicInputs {
        nullifier_value: old_private_tree_hash,
        new_leaf_value: new_private_tree_hash,
        merkle_root_value: old_root,
    };
    let private_witness = PrivateWitness {
        private_key: priv_key,
        index,
        token_id,
        token_amount: GoldilocksField(balance),
        merkle_proof,
    };

    // info!("nullifier_value: {:?}", old_private_tree_hash);
    // info!("new_leaf_value: {:?}", new_private_tree_hash);
    // info!("pub_input: {:?}", pub_input);
    //
    // info!("witness: {:?}", private_witness);

    let zk_proof = gen_private_proof(data, pub_input, private_witness, wr).unwrap();

    let mut client = Client::new(demo.clone(), priv_key, token_id, 1000, 0);
    let mut server = Server::new(demo.clone());

    client.split_and_submit(12, &mut server).unwrap();
    client.split_and_submit(13, &mut server).unwrap();
    client.split_and_submit(14, &mut server).unwrap();
    client.split_and_submit(15, &mut server).unwrap();
    client.split_and_submit(15, &mut server).unwrap();
    client.split_and_submit(15, &mut server).unwrap();
    client.split_and_submit(15, &mut server).unwrap();
    client.split_and_submit(15, &mut server).unwrap();
    client.split_and_submit(15, &mut server).unwrap();

    let (final_proof, vd, cd) = server.get_recursive_proof(0, server.proofs.len() - 1);

    test_serialization(&final_proof, &vd, &cd).unwrap();

    let conf = generate_verifier_config(&final_proof).unwrap();
    let (circom_constants, circom_gates) = generate_circom_verifier(&conf, &cd, &vd).unwrap();

    let mut circom_file = File::create("./circom/circuits/constants.circom").unwrap();
    circom_file.write_all(circom_constants.as_bytes()).unwrap();
    circom_file = File::create("./circom/circuits/gates.circom").unwrap();
    circom_file.write_all(circom_gates.as_bytes()).unwrap();

    let proof_json = generate_proof_base64(&final_proof, &conf).unwrap();

    if !Path::new("./circom/test/data").is_dir() {
        std::fs::create_dir("../../../circom/test/data").unwrap();
    }
    //input for snarkjs
    let mut proof_file = File::create("./circom/test/data/proof.json").unwrap();
    proof_file.write_all(proof_json.as_bytes()).unwrap();

    //input for snarkjs
    // let mut conf_file = File::create("./circom/test/data/conf.json").unwrap();
    // conf_file.write_all(serde_json::to_string(&conf)?.as_ref())?;
}
