//! Example of scaffolding where function uses full `GateThreaderBuilder` instead of single `Context`
use clap::Parser;
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::{GateChip, GateInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::ScalarField;
use halo2_base::AssignedValue;
#[allow(unused_imports)]
use halo2_base::{
    Context,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::arithmetic::Field;
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::run_builder_on_inputs;
use rand::rngs::OsRng;

// this algorithm takes a public input x, computes x^2 + 72, and outputs the result as public output
fn some_algorithm_in_zk<F: ScalarField>(
    builder: &mut GateThreadBuilder<F>,
    x: F,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // can still get a Context via:
    let ctx = builder.main(0); // 0 means FirstPhase, don't worry about it

    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // first we load a number `x` into as system, as a "witness"
    let x = ctx.load_witness(x);
    // by default, all numbers in the system are private
    // we can make it public like so:
    make_public.push(x);

    // create a Gate chip that contains methods for basic arithmetic operations
    let gate = GateChip::<F>::default();

    // ===== way 1 =====
    // now we can perform arithmetic operations almost like a normal program using halo2-lib API functions
    // square x
    let x_sq = gate.mul(ctx, x, x);

    // x^2 + 72
    let c = F::from(72);
    // the implicit type of most variables is an "Existing" assigned value
    // a known constant is a separate type that we specify by `Constant(c)`:
    let out = gate.add(ctx, x_sq, Constant(c));
    // Halo2 does not distinguish between public inputs vs outputs because the verifier seems them all at the same time
    // However in traditional terms, `out` is our output number. It is currently still private.
    // Let's make it public:
    make_public.push(out);
    // ==== way 2 =======
    // here is a more optimal way to compute x^2 + 72 using the lower level `assign_region` API:
    let val = *x.value() * x.value() + c;
    let _val_assigned =
        ctx.assign_region_last([Constant(c), Existing(x), Existing(x), Witness(val)], [0]);
    // the `[0]` tells us to turn on a vertical `a + b * c = d` gate at row position 0.
    // this imposes the constraint c + x * x = val

    // ==== way 3 ======
    // this does the exact same thing as way 2, but with a pre-existing function
    let _val_assigned = gate.mul_add(ctx, x, x, Constant(c));

    println!("x: {:?}", x.value());
    println!("val_assigned: {:?}", out.value());
    assert_eq!(*x.value() * x.value() + c, *out.value());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    // let's say we don't want to run prover with inputs from file
    // instead we generate inputs here:
    let private_inputs = Fr::random(OsRng);
    run_builder_on_inputs(some_algorithm_in_zk, args, private_inputs);
}
