use axiom_eth::{keccak::KeccakChip, EthChip, Field};
use clap::Parser;
use ethers_core::utils::keccak256;
use halo2_base::{gates::RangeInstructions, AssignedValue, Context};
use halo2_scaffold::scaffold::{cmd::Cli, run_eth};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub bytes: Vec<u8>,
}

/// Input is a fixed number of bytes. THE CIRCUIT DEPENDS ON THE NUMBER OF BYTES.
/// The bytes are range checked to be 8 bits each and exposed as public inputs.
/// The 32 byte keccak hash of the input bytes are exposed as public outputs.
//
// @dev `F` must be `axiom_eth::Field` instead of `ScalarField` for some technical reasons
fn compute_fixed_len_keccak<F: Field>(
    ctx: &mut Context<F>,
    eth_chip: &EthChip<F>,
    keccak: &mut KeccakChip<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) -> impl FnOnce(&mut Context<F>, &mut Context<F>, &EthChip<F>) + Clone {
    // the output is a callback function, just take this trait for granted

    // load the input
    let bytes = ctx.assign_witnesses(input.bytes.iter().map(|b| F::from(*b as u64)));
    // `EthChip` contains `RangeChip`, `Gate`
    let range = eth_chip.range();
    // Expose input as public inputs, range check each to be 8 bits
    for byte in &bytes {
        make_public.push(*byte);
        range.range_check(ctx, *byte, 8);
    }

    // Compute keccak hash of the input bytes (this only does witness generation, it does **not** constrain the computation yet)
    let hash_idx = keccak.keccak_fixed_len(ctx, range.gate(), bytes, None);
    // this only returns an index of the output in some "keccak table" (mostly for technical reasons)
    // to get the value, we have to fetch:
    let out_bytes = keccak.fixed_len_queries[hash_idx].output_assigned.clone();
    assert_eq!(out_bytes.len(), 32);
    for byte in &out_bytes {
        make_public.push(*byte);
    }

    // Just for display purposes, print the output as hex string:
    print!("Output: ");
    for b in &out_bytes {
        print!("{:02x}", b.value().get_lower_32() as u8);
    }
    println!();
    // Assert the output is correct
    let out_expected = keccak256(input.bytes);
    for (b1, b2) in out_bytes.into_iter().zip(out_expected) {
        assert_eq!(b1.value().get_lower_32(), b2 as u32);
    }

    // Here's the tricky part: you MUST provide a callback function (as a closure) for what to do in SecondPhase of the Challenge API
    // This includes any function that requires using the random challenge value

    // For Keccak, this function is empty because we fill it in for you behind the scenes. ONLY in the SecondPhase is the keccak computation above actually constrained.
    #[allow(clippy::let_and_return)]
    let callback =
        |_ctx_gate: &mut Context<F>, _ctx_rlc: &mut Context<F>, _eth_chip: &EthChip<F>| {};

    callback
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    // use run_eth instead of run
    run_eth(compute_fixed_len_keccak, args);
}
