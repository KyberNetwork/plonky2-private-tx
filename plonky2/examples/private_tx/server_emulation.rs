use std::borrow::Borrow;
use std::ops::{Deref, Index};

use anyhow::{Error, Result};
use log::info;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;

use crate::circuit;
use crate::circuit::{
    gen_recursive_circuit, recursive_circuit, ProofTuple, PublicInputs, WiringTarget,
};
use crate::state::State;

pub struct Server {
    state: State,

    config: CircuitConfig,
    tree_height: usize,
    circuit_data: CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    pub proofs: Vec<ProofTuple<GoldilocksField, PoseidonGoldilocksConfig, 2>>,
}

impl Server {
    pub fn new(state: State) -> Self {
        const D: usize = 2;

        let config = CircuitConfig::standard_recursion_config();
        let tree_height = 10;
        let (circuit_data, wiring) = circuit::private_tx_circuit::<
            GoldilocksField,
            PoseidonGoldilocksConfig,
            { D },
        >(&config, tree_height);

        Self {
            state,
            config,
            tree_height,
            circuit_data,
            proofs: vec![],
        }
    }

    pub fn verify_and_update_state(
        &mut self,
        proof: ProofTuple<GoldilocksField, PoseidonGoldilocksConfig, 2>,
        public_inp: PublicInputs<GoldilocksField>,
    ) -> Result<(usize)> {
        let current_utxo_root = self.state.private_utxo_tree.cap.0[0];

        if current_utxo_root != public_inp.merkle_root_value {
            return Err(Error::msg("wrong merkle roof value"));
        }

        match self.circuit_data.verify(proof.0.clone()) {
            Ok(..) => {
                self.state.add_nullify_utxo(public_inp.nullifier_value);
                let new_index = self.state.add_private_utxo(public_inp.new_leaf_value);
                //  push proof to vec
                self.proofs.push(proof);
                Ok(new_index)
            }
            Err(err) => Err(err),
        }
    }

    pub fn get_recursive_proof(
        &self,
        left: usize,
        right: usize,
    ) -> ProofTuple<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        info!("recur: {:?} {:?}", left, right);
        return if left == right {
            (
                self.proofs[left].0.clone(),
                VerifierOnlyCircuitData {
                    constants_sigmas_cap: self.proofs[left].1.constants_sigmas_cap.clone(),
                    circuit_digest: self.proofs[left].1.circuit_digest.clone(),
                },
                self.proofs[left].2.clone(),
            )
        } else {
            let mid = (left + right) / 2;
            let inner1 = &self.get_recursive_proof(left, mid);
            let inner2 = &self.get_recursive_proof(mid + 1, right);

            let (data1, wiring1) =
                recursive_circuit::<F, C, C, D>(inner1, inner2, &self.config, None);
            return gen_recursive_circuit::<F, C, C, D>(inner1, inner2, data1, wiring1).unwrap();
        };
    }

    pub fn get_state(&self) -> State {
        self.state.clone()
    }
}
