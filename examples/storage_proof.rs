use axiom_eth::{keccak::KeccakChip, EthChip, storage::EthStorageChip, Field, providers::get_block_storage_input};
use clap::Parser;
use halo2_base::{AssignedValue, Context, gates::RangeInstructions};
use halo2_scaffold::scaffold::{cmd::Cli, run_eth};
use serde::{Deserialize, Serialize};
use ethers_core::{types::{H160, H256}};
use ethers_providers::{Provider, Http};
use std::str::FromStr;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub provider_url: String,
    pub state_root: String,
    pub block_number: u32,
    pub addr: String,
    pub slot: u64,
    pub acct_pf_max_depth: usize,
    pub storage_pf_max_depth: usize,
}

fn compute_storage_proof_at_slot<F: Field>(
    ctx: &mut Context<F>,
    eth_chip: &EthChip<F>,
    keccak: &mut KeccakChip<F>,
    input: CircuitInput,
    _: &mut Vec<AssignedValue<F>>,
) -> impl FnOnce(&mut Context<F>, &mut Context<F>, &EthChip<F>) + Clone {
    let provider = Provider::<Http>::try_from(input.provider_url.as_str()).unwrap();
    let slot = H256::from_low_u64_be(input.slot);
    let state_root = H256::from_str(&input.state_root).unwrap();
    let address = H160::from_str(&input.addr).unwrap();

    //To prove the storage trace we first need to fetch a fixed length keccak MPT proof.
    // This will be used as a constraint to generate the storage trace.
    let mpt_fixed_proof = get_block_storage_input(
        &provider, 
        input.block_number, 
        address,
        vec![slot],
        input.acct_pf_max_depth, 
        input.storage_pf_max_depth
    ).storage.storage_pfs[0].clone().2.assign(ctx);

    //Assign state_root and slot as private witnesses
    let state_root_bytes = ctx.assign_witnesses(state_root.to_fixed_bytes().map(|b| F::from(b as u64)));
    let slot_bytes = ctx.assign_witnesses(slot.to_fixed_bytes().map(|b| F::from(b as u64)));

    //Range check byte values to 8 bits
    //TODO: check if this is redundant within the eth_chip
    let range = eth_chip.range();
    for (state_root_byte, slot_byte) in state_root_bytes.clone().into_iter().zip(slot_bytes.clone().into_iter()) {
        range.range_check(ctx, state_root_byte, 8);
        range.range_check(ctx, slot_byte, 8);
    }

    //Perform witness generation of storage proof
    let storage_trace_witness = eth_chip.parse_storage_proof_phase0(ctx, keccak, &mpt_fixed_proof.root_hash_bytes, slot_bytes, mpt_fixed_proof.clone());
    #[allow(clippy::let_and_return)]
    let callback =
        |ctx_gate: &mut Context<F>, ctx_rlc: &mut Context<F>, eth_chip: &EthChip<F>| {
            // Constrain witness proof generation
            eth_chip.parse_storage_proof_phase1((ctx_gate, ctx_rlc), storage_trace_witness);
        };
    callback
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    // use run_eth instead of run
    run_eth(compute_storage_proof_at_slot, args);
}