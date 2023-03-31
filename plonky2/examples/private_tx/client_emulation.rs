use std::sync::Arc;

use anyhow::Result;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::merkle_tree::{MerkleCap, MerkleTree};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;

use crate::circuit;
use crate::circuit::{PrivateWitness, ProofTuple, PublicInputs};
use crate::server_emulation::Server;
use crate::state::State;

pub struct Client {
    state: State,
    //mock, this should be from server
    priv_key: [GoldilocksField; 4],
    token_id: GoldilocksField,
    balance: u64,
    priv_index: usize,
    config: CircuitConfig,
    tree_height: usize,
}

impl Client {
    //state must include a leaf with priv_key
    pub fn new(
        priv_key: [GoldilocksField; 4],
        token_id: GoldilocksField,
        balance: u64,
        priv_index: usize,
    ) -> Self {
        Self {
            state: State {
                private_utxo_tree: MerkleTree {
                    leaves: vec![],
                    digests: vec![],
                    cap: MerkleCap(vec![]),
                },
                next_index_utxo: 0,
                nullify_utxo_tree: MerkleTree {
                    leaves: vec![],
                    digests: vec![],
                    cap: MerkleCap(vec![]),
                },
                next_index_nullify: 0,
                merkle_cap_height: 0,
            },
            priv_key,
            token_id,
            balance,
            priv_index,
            config: CircuitConfig::standard_recursion_config(),
            tree_height: 10,
        }
    }

    pub fn get_state_from_server(&mut self, server: &Server) {
        self.state = server.get_state()
    }

    pub fn split_and_submit(&mut self, delta: u64, server: &mut Server) -> Result<()> {
        const D: usize = 2;

        assert!(delta <= self.balance, "can't split more than what you have");
        let old_private_tree_hash = PoseidonHash::hash_no_pad(
            &[
                self.priv_key,
                [
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    self.token_id,
                    GoldilocksField::from_canonical_u64(self.balance),
                ],
            ]
            .concat(),
        );
        let merkle_proof = self.state.private_utxo_merkle_proof(self.priv_index);
        let old_root = self.state.private_utxo_tree.cap.0[0];
        let new_private_tree_hash = PoseidonHash::hash_no_pad(
            &[
                self.priv_key,
                [
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    self.token_id,
                    GoldilocksField::from_canonical_u64(self.balance - delta),
                ],
            ]
            .concat(),
        );
        //TODO: Credit an account
        let p_witness = PrivateWitness {
            private_key: self.priv_key,
            index: self.priv_index,
            token_id: self.token_id,
            token_amount: GoldilocksField::from_canonical_u64(self.balance),
            merkle_proof,
        };
        let public_inp = PublicInputs {
            nullifier_value: old_private_tree_hash,
            merkle_root_value: old_root,
            new_leaf_value: new_private_tree_hash,
        };

        println!(
            "{:?} {:?} {:?}",
            p_witness.token_amount, public_inp.nullifier_value, public_inp.new_leaf_value
        );

        //Generate a proof of our privateTX
        let (circuit_data, wiring) = circuit::private_tx_circuit::<
            GoldilocksField,
            PoseidonGoldilocksConfig,
            D,
        >(&self.config, self.tree_height);
        let proof = circuit::gen_private_proof::<GoldilocksField, PoseidonGoldilocksConfig, D>(
            circuit_data,
            public_inp.clone(),
            p_witness,
            wiring,
        )?;

        // //  re-update state
        self.priv_index = server
            .verify_and_update_state(proof, public_inp.clone())
            .unwrap();
        self.balance = self.balance - delta;
        self.get_state_from_server(server);

        Ok(())
        //We don't need to verify this. let's the server do it.
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::{Field, Sample};

    use crate::client_emulation::Client;
    use crate::server_emulation::Server;
    use crate::state::State;

    #[test]
    fn test_client_split() -> Result<()> {
        let tree_height = 10;
        let prive_key: [GoldilocksField; 4] = GoldilocksField::rand_array();
        let token_id = GoldilocksField::from_canonical_u64(1);
        let balance: u64 = 1000;
        let (demoState, index) = State::new_demo_state(prive_key, token_id, balance, 10);
        let proof = demoState.private_utxo_tree.prove(index);
        let token_id = GoldilocksField(1);

        let mut client = Client::new(prive_key, token_id, balance, 0);
        let mut server = Server::new(demoState.clone());
        client.get_state_from_server(&server);
        client.split_and_submit(12, &mut server).unwrap();
        Ok(())
    }
}
