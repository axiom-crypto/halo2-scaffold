use std::env::var;

use clap::Parser;
use halo2_base::gates::{GateInstructions, RangeChip};
use halo2_base::safe_types::RangeInstructions;
use halo2_base::utils::ScalarField;
use halo2_base::AssignedValue;
#[allow(unused_imports)]
use halo2_base::{
    Context,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::run;
use serde::{Deserialize, Serialize};

// #### Integer division

// Write a circuit which constrains the following function:
// ```
// public inputs:
// * A non-negative integer x, which is guaranteed to be at most 16-bits

// public outputs:
// * The non-negative integer (x / 32), where "/" represents integer division.
// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub x: String, // field element, but easier to deserialize as a string
    pub out: String,
}

fn int_div_32<F: ScalarField>(
    ctx: &mut Context<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let x = F::from_str_vartime(&input.x).unwrap();
    // private
    let x = ctx.load_witness(x);
    // public
    make_public.push(x);

    // needs to be compatible with some backend setup, so read from environmental variable
    let lookup_bits =
        var("LOOKUP_BITS").unwrap_or_else(|_| panic!("LOOKUP_BITS not set")).parse().unwrap();
    // range chip uses a lookup table with precomputed numbers 0..2^lookup_bits
    let range = RangeChip::default(lookup_bits);

    // let x_u32 = x.value().get_lower_32();
    // compute witnesses so that x_u32 = quot * 32 + rem
    // let quot = x_u32 / 32;
    // let rem = x_u32 % 32;

    // check quot and rem are both at most 5 bits so `quot * 32 + rem` doesn't overflow
    // quot * 32 + rem = x
    // rem in [0, 32)
    // by default: you're checking quot * 32 + rem = x (mod modulus of F)
    // TEMPORARY: SKIP THIS RANGE CHECK:
    // check quot is at most 16 - log2_floor(32) = 11 bits
    // We can find (quot, rem) such that quot * 32 + rem = x (mod modulus of F)
    // rem = 0
    // quot = x * (32)^{-1} (mod modulus of F)
    // quot will be really big
    // but quot * 32 = x in F
    let rem = F::zero();
    let quot = *x.value() * F::from(32).invert().unwrap();
    dbg!(quot);
    let [quot, rem] = [quot, rem].map(|a| ctx.load_witness(a));
    // range.range_check(ctx, quot, 11);
    range.check_less_than_safe(ctx, rem, 32);

    let x_check = range.gate().mul_add(ctx, quot, Constant(F::from(32)), rem);
    ctx.constrain_equal(&x, &x_check);

    // range.range_check(ctx, x, 16);
    // let (quot, rem) = range.div_mod(ctx, x, 32u64, 16);

    make_public.push(quot);
    //assert_eq!(quot.value(), &F::from_str_vartime(&input.out).unwrap());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    // run different zk commands based on the command line arguments
    run(int_div_32, args);
}
