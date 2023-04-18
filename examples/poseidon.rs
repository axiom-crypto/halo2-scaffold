use clap::Parser;
use halo2_base::{gates::GateChip, utils::ScalarField, AssignedValue, Context};
use halo2_scaffold::scaffold::{cmd::Cli, run};
use poseidon::PoseidonChip;
use serde::{Deserialize, Serialize};

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub inputs: [String; 2], // two field elements, but as strings for easier deserialization
}

fn hash_two<F: ScalarField>(
    ctx: &mut Context<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // first we load a private input `x` (let's not worry about public inputs for now)
    let [x, y] = inp.inputs.map(|x| ctx.load_witness(F::from_str_vartime(&x).unwrap()));
    make_public.extend([x, y]);

    // create a Gate chip that contains methods for basic arithmetic operations
    let gate = GateChip::<F>::default();
    let mut poseidon = PoseidonChip::<F, T, RATE>::new(ctx, R_F, R_P).unwrap();
    poseidon.update(&[x, y]);
    let hash = poseidon.squeeze(ctx, &gate).unwrap();
    make_public.push(hash);
    println!("x: {:?}, y: {:?}, poseidon(x): {:?}", x.value(), y.value(), hash.value());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    run(hash_two, args);
}
