use clap::Parser;
use halo2_base::gates::GateInstructions;
use halo2_base::gates::RangeChip;
use halo2_base::gates::RangeInstructions;
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
use std::env::var;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub array: Vec<String>,
    pub start: String,
    pub end: String,
}

// this algorithm takes a public input x, computes x^2 + 72, and outputs the result as public output
fn variable_subarray_shift<F: ScalarField>(
    ctx: &mut Context<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let array = input
        .array
        .iter()
        .map(|x| F::from_str_vartime(x).expect("deserialize field element should not fail"))
        .collect::<Vec<_>>();

    let start =
        F::from_str_vartime(&input.start).expect("deserialize field element should not fail");

    let end = F::from_str_vartime(&input.end).expect("deserialize field element should not fail");

    // check input
    // should add assertion to prover code?
    assert!(array.len() == 1000);
    assert!(start < end);
    assert!(start < F::from(1000));
    assert!(end < F::from(1000));

    let witness_array = ctx.assign_witnesses(array.clone());
    let start = ctx.load_witness(start);
    let end = ctx.load_witness(end);

    for witness in &witness_array {
        make_public.push(*witness);
    }

    make_public.push(start);
    make_public.push(end);

    let lookup_bits =
        var("LOOKUP_BITS").unwrap_or_else(|_| panic!("LOOKUP_BITS not set")).parse().unwrap();

    // create a Gate chip that contains methods for basic arithmetic operations
    let range: RangeChip<F> = RangeChip::default(lookup_bits);

    // array size = 10 < 2^4
    let bits = range.gate().num_to_bits(ctx, start, 10);
    let sub_array_size = range.gate().sub(ctx, end, start);

    let mut current_array = witness_array;
    // shift array by start
    for i in 0..10 {
        let shift_per_bit = 2_usize.pow(i as u32);
        let next_array: Vec<AssignedValue<F>> = current_array
            .iter()
            .enumerate()
            .map(|(idx, cell)| {
                let shift_for_this_cell = (idx + shift_per_bit) % 1000;
                range.gate().select(
                    ctx,
                    *current_array.get(shift_for_this_cell).unwrap(),
                    *cell,
                    *bits.get(i).unwrap(),
                )
            })
            .collect();
        current_array = next_array;
    }

    let masks = (0..1000)
        .map(|i| range.is_less_than(ctx, Constant(F::from(i)), sub_array_size, 10))
        .collect::<Vec<_>>();

    let output = masks
        .iter()
        .enumerate()
        .map(|(i, mask)| range.gate().mul(ctx, *mask, *current_array.get(i as usize).unwrap()))
        .collect::<Vec<_>>();

    for cell in &output {
        make_public.push(*cell);
    }

    println!("array: {:?}", array);
    println!("start: {:?}", start.value());
    println!("end: {:?}", end.value());

    println!("output: {:?}", output.iter().map(|x| x.value()).collect::<Vec<_>>());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    // run different zk commands based on the command line arguments
    run(variable_subarray_shift, args);
}
