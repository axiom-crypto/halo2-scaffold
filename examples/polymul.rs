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
// - The input polynomials are not made public
// - Suppoe that range check is performed on the coeffiicients in order to avoid overflow for happen during the multiplication
// - Patterned after https://github.com/yi-sun/circom-pairing/blob/master/circuits/bigint.circom#L227

const DEGREE: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput<const DEGREE: usize> {
    pub a: Vec<u8>, // polynomial coefficients big endian of degree DEGREE
    pub b: Vec<u8>, // polynomial coefficients big endian of degree DEGREE
}

// this algorithm takes two polynomials a and b of the same degree and output their product to the public
fn some_algorithm_in_zk<F: ScalarField>(
    ctx: &mut Context<F>,
    input: CircuitInput<DEGREE>,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // assert that the input polynomials have the same degree
    assert_eq!(input.a.len() - 1, input.b.len() - 1);
    // assert that degree is equal to the constant DEGREE
    assert_eq!(input.a.len() - 1, DEGREE);

    // Compute the product of two polynomials (precomputated outside of the circuit)
    let mut prod_val = vec![0; 2 * DEGREE - 1];

    for i in 0..(2 * DEGREE - 1) {
        if i < DEGREE {
            for a_idx in 0..=i {
                prod_val[i] += input.a[a_idx] * input.b[i - a_idx];
            }
        } else {
            for a_idx in (i - DEGREE + 1)..DEGREE {
                prod_val[i] += input.a[a_idx] * input.b[i - a_idx];
            }
        }
    }

    // assert that the output polynomial has the correct degree
    assert_eq!(prod_val.len(), 2 * DEGREE - 1);

    // create a vector of vectors to cache the exponents for different x values in range [0, 2 * k - 1)
    // exps[i][j] = i^j exponent
    let mut exps = vec![vec![0; 2 * DEGREE - 1]; 2 * DEGREE - 1];

    for i in 0..(2 * DEGREE - 1) {
        for j in 0..(2 * DEGREE - 1) {
            exps[i][j] = (i as u64).pow(j as u32);
        }
    }

    // Evaluate the polynomial a, b, prod for x values in [0, 2 * k - 1) (precomputed outside of the circuit)
    let mut a_evals = vec![0_u64; 2 * DEGREE - 1];
    let mut b_evals = vec![0_u64; 2 * DEGREE - 1];
    let mut prod_evals = vec![0_u64; 2 * DEGREE - 1];

    for i in 0..(2 * DEGREE - 1) {
        for j in 0..(2 * DEGREE - 1) {
            prod_evals[i] += prod_val[j] as u64 * (exps[i][j] as u64);
        }

        for j in 0..DEGREE {
            a_evals[i] += input.a[j] as u64 * (i as u64).pow(j as u32);
            b_evals[i] += input.b[j] as u64 * (i as u64).pow(j as u32);
        }
    }

    // Now let's assign the precomputed values inside the circuit
    let a_evals_assigned: Vec<AssignedValue<F>> = a_evals
        .iter()
        .map(|x| {
            let result = F::from(*x);
            ctx.load_witness(result)
        })
        .collect();

    let b_evals_assigned: Vec<AssignedValue<F>> = b_evals
        .iter()
        .map(|x| {
            let result = F::from(*x);
            ctx.load_witness(result)
        })
        .collect();

    let prod_evals_assigned: Vec<AssignedValue<F>> = prod_evals
        .iter()
        .map(|x| {
            let result = F::from(*x);
            ctx.load_witness(result)
        })
        .collect();

    // assert the correct length of the assigned polynomails
    assert_eq!(a_evals_assigned.len(), b_evals_assigned.len());
    assert_eq!(b_evals_assigned.len(), prod_evals_assigned.len());

    // Enforce that a_evals_assigned[i] * b_evals_assigned[i] = prod_evals_assigned[i]
    let gate = GateChip::<F>::default();
    for i in 0..(2 * DEGREE - 1) {
        let val =
            gate.mul_add(ctx, a_evals_assigned[i], b_evals_assigned[i], prod_evals_assigned[i]);
        make_public.push(val);
    }
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    // run different zk commands based on the command line arguments
    run(some_algorithm_in_zk, args);
}
