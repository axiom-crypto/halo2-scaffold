use axiom_eth::{
    keccak::KeccakChip,
    util::{bytes_be_to_u128, uint_to_bytes_be},
    EthChip, Field,
};
use clap::Parser;
use halo2_base::{gates::RangeInstructions, AssignedValue, Context};
use halo2_scaffold::scaffold::{cmd::Cli, run_eth};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub bytes31: String, // 1 field elements, but as strings for easier deserialization
    pub max_len: u64, // maximum length in bytes of the input string
}

// Like the fixed length example we supply `bytes31` representing `31` bytes. We decompose the field eleemnt in big endian into 31 bytes.
// We also supply the maximum length in bytes to compute the keccak hash over.
// Then we compute the variable length keccak hash over `max_len` of the 31 bytes and output the hash as two field elements in hi-lo (u128, u128) form
// @dev `F` must be `axiom_eth::Field` instead of `ScalarField` for some technical reasons
fn compute_var_len_keccak<F: Field>(
    ctx: &mut Context<F>,
    eth_chip: &EthChip<F>,
    keccak: &mut KeccakChip<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) -> impl FnOnce(&mut Context<F>, &mut Context<F>, &EthChip<F>) + Clone {
    // the output is a callback function, just take this trait for granted

    // load the input value as a witness
    let x = ctx.load_witness(F::from_str_vartime(&inp.bytes31).unwrap());
    // We supply the `max_len` as a witness as we need to range check it to the size of the input before performing the keccak computation
    let max_len = ctx.load_witness(F::from(inp.max_len));
    make_public.push(x);

    // x is a single field element, which can fit up to ~254 bits

    // `EthChip` contains `RangeChip`, `Gate`
    let range = eth_chip.range();
    // Decompose x into 31 bytes, using a utility function from axiom-eth
    let bytes = uint_to_bytes_be(ctx, range, &x, 31);

    // To perform variable length keccak we supply the range of bytes we want to hash over (min_len..max_len)
    // We perform a range check on this range behind the scenes to confirm we are hashing over a valid range of the input
    // For faster witness generation, we can supply the raw bytes of the input
    let hash_idx = keccak.keccak_var_len(ctx, range, bytes, Some(inp.bytes31.into_bytes()), max_len, 0);

    // Fetch the value of the variable length keccak hash from the "keccak table"
    let out_bytes32 = keccak.var_len_queries[hash_idx].output_assigned.clone();
    let out_hilo = bytes_be_to_u128(ctx, range.gate(), &out_bytes32);
    assert_eq!(out_hilo.len(), 2);
    for o in out_hilo {
        make_public.push(o);
    }

    // Print the output as byte string:
    print!("Output: ");
    for b in out_bytes32 {
        print!("{:02x}", b.value().get_lower_32() as u8);
    }
    println!();

    // Same as fixed length keccak, we supply a callback function specifying what to do in the second phase of the Challenge API. 
    // Since we're just calculating a variable length hash, we don't need to do anything here
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