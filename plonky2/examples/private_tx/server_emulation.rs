use anyhow::{Error, Result};

use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;
use crate::circuit;
use crate::circuit::{ProofTuple, PublicInputs, WiringTarget};
use crate::state::State;

pub struct Server {
    state: State,

    config: CircuitConfig,
    tree_height: usize,
    circuit_data: CircuitData<GoldilocksField, PoseidonGoldilocksConfig, { 2 }>,
}

impl Server {
    pub fn new(state: State) -> Self {
        const D: usize = 2;

        let config = CircuitConfig::standard_recursion_config();
        let tree_height = 10;
        let (circuit_data, wiring) = circuit::private_tx_circuit::<GoldilocksField, PoseidonGoldilocksConfig, { D }>(&config, tree_height);

        Self {
            state,
            config,
            tree_height,
            circuit_data,
        }
    }

    pub fn verify_and_update_state(
        &mut self,
        proof: ProofTuple<GoldilocksField, PoseidonGoldilocksConfig, 2>,
        public_inp: PublicInputs<GoldilocksField>
    ) -> Result<(usize)> {
        let current_utxo_root = self.state.private_utxo_tree.cap.0[0];

        if current_utxo_root != public_inp.merkle_root_value {
            return Err(Error::msg("wtf"))
        }

        match self.circuit_data.verify(proof.0.clone()) {
            Ok(..) => {
                self.state.add_nullify_utxo(public_inp.nullifier_value);
                let new_index = self.state.add_private_utxo(public_inp.new_leaf_value);
                Ok(new_index)
            }
            Err(err) => {
                Err(err)
            }
        }
    }
}