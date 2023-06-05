use axiom_eth::{keccak::KeccakChip, EthChip, Field};
use clap::Parser;
use ethers_core::utils::keccak256;
use halo2_base::{gates::RangeInstructions, AssignedValue, Context};
use halo2_scaffold::scaffold::{cmd::Cli, run_eth};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub padded_bytes: Vec<u8>, // input bytes, right padded with arbitrary bytes to fixed `MAX_LEN`
    pub len: usize,            // the variable length of the input bytes
}

/// Variable length byte arrays are expressed as a fixed length byte array of length `MAX_LEN`, right padded with arbitrary bytes (typically 0s), together with the actual length of the input bytes.
/// The bytes (including padding bytes) are range checked to be 8 bits each and exposed as public inputs.
/// The 32 byte keccak hash of `padded_bytes[..len]` are exposed as public outputs.
//
// @dev `F` must be `axiom_eth::Field` instead of `ScalarField` for some technical reasons
fn compute_var_len_keccak<F: Field>(
    ctx: &mut Context<F>,
    eth_chip: &EthChip<F>,
    keccak: &mut KeccakChip<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) -> impl FnOnce(&mut Context<F>, &mut Context<F>, &EthChip<F>) + Clone {
    // the output is a callback function, just take this trait for granted

    // load the input
    let padded_bytes = ctx.assign_witnesses(input.padded_bytes.iter().map(|b| F::from(*b as u64)));
    let _max_len = padded_bytes.len();
    let len = ctx.load_witness(F::from(input.len as u64));

    // `EthChip` contains `RangeChip`, `Gate`
    let range = eth_chip.range();
    // Expose input as public inputs, range check each to be 8 bits
    for byte in &padded_bytes {
        make_public.push(*byte);
        range.range_check(ctx, *byte, 8);
    }
    make_public.push(len);

    // A range check is done behind-the-scenes in `keccak_var_len`: range.check_less_than_safe(ctx, len, max_len as u64 + 1);
    // This will compute the keccak hash of `padded_bytes[..len]` (this only does witness generation, it does **not** constrain the computation yet)
    let hash_idx = keccak.keccak_var_len(ctx, range, padded_bytes, None, len, 0);
    // this only returns an index of the output in some "keccak table" (mostly for technical reasons)
    // to get the value, we have to fetch:
    let out_bytes = keccak.var_len_queries[hash_idx].output_assigned.clone();
    assert_eq!(out_bytes.len(), 32);
    for byte in &out_bytes {
        make_public.push(*byte);
    }

    // Print the output as byte string:
    print!("Output: ");
    for b in &out_bytes {
        print!("{:02x}", b.value().get_lower_32() as u8);
    }
    println!();
    // To clarify what the output is actually computing:
    let len = len.value().get_lower_32() as usize;
    let out_expected = keccak256(&input.padded_bytes[..len]);
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
    run_eth(compute_var_len_keccak, args);
}
