use std::env::var;

use clap::Parser;
use halo2_base::gates::{GateChip, GateInstructions, RangeChip};
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
    let range = RangeChip::default(lookup_bits);

    let x_u32 = x.value().get_lower_32();
    let quot = x_u32 / 32;
    let rem = x_u32 % 32;

    let [quot, rem] = [quot, rem].map(|a| ctx.load_witness(F::from(a as u64)));
    // check quot and rem are both at most 5 bits so `quot * 32 + rem` doesn't overflow
    range.range_check(ctx, quot, 5);
    range.range_check(ctx, rem, 5);

    let x_check = range.gate().mul_add(ctx, quot, Constant(F::from(32)), rem);
    ctx.constrain_equal(&x, &x_check);

    make_public.push(quot);
    assert_eq!(quot.value(), &F::from_str_vartime(&input.out).unwrap());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    // run different zk commands based on the command line arguments
    run(int_div_32, args);
}
