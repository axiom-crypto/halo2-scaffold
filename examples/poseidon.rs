use halo2_base::{
    gates::GateChip, halo2_proofs::halo2curves::bn256::Fr, utils::ScalarField, AssignedValue,
    Context,
};
use halo2_proofs::arithmetic::Field;
#[allow(unused_imports)]
use halo2_scaffold::scaffold::{mock, prove};
use poseidon::PoseidonChip;
use rand::rngs::OsRng;

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

fn hash_two<F: ScalarField>(
    ctx: &mut Context<F>,
    [x, y]: [F; 2],
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // first we load a private input `x` (let's not worry about public inputs for now)
    let [x, y] = [x, y].map(|x| ctx.load_witness(x));
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

    // run mock prover
    mock(hash_two, [(); 2].map(|_| Fr::random(OsRng)));

    // uncomment below to run actual prover:
    // prove(hash_two, [(); 2].map(|_| Fr::random(OsRng)), [Fr::zero(); 2]);
}
