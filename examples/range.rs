use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::ScalarField;
use halo2_base::{AssignedValue, Context};
#[allow(unused_imports)]
use halo2_scaffold::scaffold::{mock, prove};
use rand::random;
use std::env::var;

fn some_algorithm_in_zk<F: ScalarField>(
    ctx: &mut Context<F>,
    x: F,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // lookup bits must agree with the size of the lookup table, which is specified by an environmental variable
    let lookup_bits =
        var("LOOKUP_BITS").unwrap_or_else(|_| panic!("LOOKUP_BITS not set")).parse().unwrap();
    // first we load a private input `x`
    let x = ctx.load_witness(x);
    // make it public
    make_public.push(x);

    // create a Range chip that contains methods for basic arithmetic operations
    let range = RangeChip::default(lookup_bits);

    // check that `x` is in [0, 2^64)
    range.range_check(ctx, x, 64);

    // RangeChip contains GateChip so you can still do basic operations:
    let _sum = range.gate().add(ctx, x, x);
}

fn main() {
    env_logger::init();

    // run mock prover
    mock(some_algorithm_in_zk, Fr::from(random::<u64>()));

    // uncomment below to run actual prover:
    // prove(some_algorithm_in_zk, Fr::from(random::<u64>()), Fr::zero());
}
