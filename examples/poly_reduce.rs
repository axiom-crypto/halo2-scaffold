use std::env::var;
use clap::Parser;
use halo2_base::safe_types::{RangeChip, RangeInstructions};
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
const MODULUS: usize = 11;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub poly: Vec<u8>, // polynomial coefficients big endian of degree DEGREE
    pub out: Vec<u8>, // polynomial coefficients big endian of degree DEGREE
}

// takes a polynomial represented by its coefficients in a vector (public input)
// and output a new polynomial reduced mod MODULUS (public output)
fn reduce_poly<F: ScalarField>(
    ctx: &mut Context<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {

	// Assert that degree is equal to the constant DEGREE
    assert_eq!(input.poly.len() - 1, DEGREE);

    // Assign the input polynomials to the circuit
    let in_assigned: Vec<AssignedValue<F>> = input
        .poly
        .iter()
        .map(|x| {
            let result = F::from(*x as u64);
            ctx.load_witness(result) // load the input as a witness
        })
        .collect();

	// needs to be compatible with some backend setup for lookup table to do range check
	// so read from environemntal variable
	let lookup_bits = var("LOOKUP_BITS").unwrap_or_else(|_| panic!("LOOKUP_BITS nto set")).parse().unwrap();

	// instead of GateChip create a RangeChip, which allows you to do range check
	let range = RangeChip::default(lookup_bits);

	// Enforce that in_assigned[i] % MODULUS = rem_assigned[i]
	let rem_assigned: Vec<AssignedValue<F>> = in_assigned
	.iter()
	.take(2 * DEGREE - 1)
	.map(|&x|range.div_mod(ctx, x, MODULUS, 4).1) // rem: [0, 11) <- at most 4 (log2_fllor(11)) bits
	.collect();

	// make the output public
	for i in 0..(DEGREE - 1) {
		make_public.push(rem_assigned[i]);
	}

	// check that rem_assined = output of the circuit
	let out_expected = input.out;

	for (rem, out) in rem_assigned.iter().zip(out_expected) {
        assert_eq!(rem.value().get_lower_32(), out as u32);
    }
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    // run different zk commands based on the command line arguments
    run(reduce_poly, args);
}