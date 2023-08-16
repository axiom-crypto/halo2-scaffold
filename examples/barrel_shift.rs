use clap::Parser;
use halo2_base::gates::{GateChip, GateInstructions};
use halo2_base::utils::ScalarField;
use halo2_base::AssignedValue;
#[allow(unused_imports)]
use halo2_base::{
    Context,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::{run, run_builder_on_inputs};
use serde::{Deserialize, Serialize};

// #### Variable subarray shift

// Write a circuit which constrains the following function:
// ```
// public inputs:
// * An array `arr` of length 1000
// * `start`, an index guaranteed to be in `[0, 1000)`
// * `end`, an index guaranteed to be in `[0, 1000)`
// * It is also known that `start <= end`

// public outputs:
// * An array `out` of length 1000 such that
//   * the first `end - start` entries of `out` are the subarray `arr[start:end]`
//   * all other entries of `out` are 0.
// ```

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub arr: Vec<u64>,
    pub start: usize,
    pub end: usize,
}

// this algorithm takes a public input x, computes x^2 + 72, and outputs the result as public output
fn var_subarray<F: ScalarField>(
    ctx: &mut Context<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let mut arr = ctx.assign_witnesses(input.arr.into_iter().map(F::from));
    //assert_eq!(arr.len(), 1000);
    let [start, end] = [input.start, input.end].map(|x| ctx.load_witness(F::from(x as u64)));
    for a in &arr {
        make_public.push(*a);
    }
    make_public.push(start);
    make_public.push(end);

    let gate = GateChip::default();
    // shift left by start
    let bits = gate.num_to_bits(ctx, start, 10);
    for (d, bit) in bits.into_iter().enumerate() {
        for i in 0..1000 {
            // arr[i] = bit ? arr[i + 2^d] : arr[i]
            // let shift = arr.get(i + (1 << d)).map(|x| Existing(*x)).unwrap_or(Constant(F::zero()));
            let shift = if i + (1 << d) < arr.len() {
                Existing(arr[i + (1 << d)])
            } else {
                Constant(F::zero())
            };
            arr[i] = gate.select(ctx, shift, arr[i], bit);
        }
    }

    // mask
    let mask_len = gate.sub(ctx, end, start);
    let mask: Vec<bool> = (0..1000).map(|i| i < input.end - input.start).collect();
    // assign as witnesses only
    let mut mask = ctx.assign_witnesses(mask.into_iter().map(|x| F::from(x)));
    for i in 1..1000 {
        gate.assert_bit(ctx, mask[i]);
        mask[i] = gate.and(ctx, mask[i], mask[i - 1]);
    }
    let check_len = gate.sum(ctx, mask.clone());
    ctx.constrain_equal(&mask_len, &check_len);

    // output
    for i in 0..1000 {
        arr[i] = gate.mul(ctx, arr[i], mask[i]);
        println!("{:?}", arr[i].value());
    }
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    let arr = (0..1000).collect();
    let input = CircuitInput { arr, start: 5, end: 10 };
    // run different zk commands based on the command line arguments
    run_builder_on_inputs(
        |builder, input, public| var_subarray(builder.main(0), input, public),
        args,
        input,
    );
}
