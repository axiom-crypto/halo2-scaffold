use clap::Parser;
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::utils::ScalarField;
use halo2_base::AssignedValue;
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::run;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub x: String, // field element, but easier to deserialize as a string
}

fn some_algorithm_in_zk<F: ScalarField>(
    builder: &mut BaseCircuitBuilder<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // create a Range chip that contains methods for basic arithmetic operations
    let range = builder.range_chip();
    let ctx = builder.main(0);

    let x = F::from_str_vartime(&input.x).expect("deserialize field element should not fail");
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // first we load a private input `x`
    let x = ctx.load_witness(x);
    // make it public
    make_public.push(x);

    // check that `x` is in [0, 2^64)
    range.range_check(ctx, x, 64);

    // RangeChip contains GateChip so you can still do basic operations:
    let _sum = range.gate().add(ctx, x, x);
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    // run different zk commands based on the command line arguments
    run(some_algorithm_in_zk, args);
}
