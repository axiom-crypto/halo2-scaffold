use clap::Parser;
use halo2_base::gates::GateChip;
use halo2_base::safe_types::GateInstructions;
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

// Note:
// - The polynomial are not made public to the outside
// - Suppoe that range check is performed on the coeffiicients in order to avoid overflow for happen during the addition

const DEGREE: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput<const DEGREE: usize> {
    pub a: Vec<u8>, // polynomial coefficients big endian of degree DEGREE
    pub b: Vec<u8>, // polynomial coefficients big endian of degree DEGREE
}

// this algorithm takes two polynomials a and b of the same degree and output their sum to the public
fn some_algorithm_in_zk<F: ScalarField>(
    ctx: &mut Context<F>,
    input: CircuitInput<DEGREE>,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // assert that the input polynomials have the same degree
    assert_eq!(input.a.len() - 1, input.b.len() - 1);
    // assert that degree is equal to the constant DEGREE
    assert_eq!(input.a.len() - 1, DEGREE);

    // Assign the input polynomials to the circuit
    let a_assigned: Vec<AssignedValue<F>> = input
        .a
        .iter()
        .map(|x| {
            let result = F::from(*x as u64);
            ctx.load_witness(result)
        })
        .collect();

    let b_assigned: Vec<AssignedValue<F>> = input
        .b
        .iter()
        .map(|x| {
            let result = F::from(*x as u64);
            ctx.load_witness(result)
        })
        .collect();

    // assert the correct length of the assigned polynomails
    assert_eq!(a_assigned.len(), b_assigned.len());

    // Enforce that a_assigned[i] * b_assigned[i] = sum_assigned[i]
    let gate = GateChip::<F>::default();
    let sum_assigned: Vec<AssignedValue<F>> = a_assigned
        .iter()
        .zip(b_assigned.iter())
        .take(2 * DEGREE - 1)
        .map(|(&a, &b)| gate.add(ctx, a, b))
        .collect();

    for i in 0..(DEGREE - 1) {
        make_public.push(sum_assigned[i]);
    }
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    // run different zk commands based on the command line arguments
    run(some_algorithm_in_zk, args);
}
