use anyhow::{Error, Result};

use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;
use crate::circuit;
use crate::circuit::WiringTarget;
use crate::state::State;

const D: usize = 2;

pub struct Server {
    state: State,

    config: CircuitConfig,
    tree_height: usize,
    circuit_data: CircuitData<F, C, D>,
}

impl Server {
    pub fn new(state: State) -> Self {

        let config = CircuitConfig::standard_recursion_config();
        let tree_height = 10;
        let (circuit_data, wiring) = circuit::private_tx_circuit::<GoldilocksField, PoseidonGoldilocksConfig, D>(&config, tree_height);

        Self {
            state,
            config,
            tree_height,
            circuit_data,
        }
    }

    pub fn verify_and_update_state<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
        &mut self,
        proof: ProofTuple<F, C, D>,
        old_utxo_root: HashOut<GoldilocksField>,
        new_leaf: HashOut<GoldilocksField>,
        new_leaf_index: usize,
        nullifier: HashOut<GoldilocksField>,
        nullifier_index: usize,
    ) -> Result<()> {
        let current_utxo_root = self.state.private_utxo_tree.cap.0[0];

        if current_utxo_root != old_utxo_root {
            Err("UTXO Root doesn't match")
        }

        match self.circuit_data.verify(proof) {
            Ok(..) => {
                // utxo root comprision
                self.state.add_private_utxo(new_leaf, new_leaf_index);
                self.state.nullify_utxo_tree(nullifier, nullifier_index);
                Ok()
            }
            Err(err) => {
                err
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Sample;
    use crate::state::State;

    #[test]
    fn test_server_split() -> Result<()> {
        let tree_height = 10;
        let prive_key: [GoldilocksField; 4] = GoldilocksField::rand_array();
        let (demo, index) = State::new_demo_state(prive_key, GoldilocksField::rand(), 10000, 10);
        let proof = demo.private_utxo_tree.prove(index);
        Ok(())
    }
}