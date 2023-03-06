use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_base::halo2_proofs::plonk::{create_proof, verify_proof};
use halo2_base::halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use halo2_base::utils::ScalarField;
use halo2_base::{
    gates::{
        builder::{GateCircuitBuilder, GateThreadBuilder},
        GateChip, GateInstructions,
    },
    halo2_proofs::plonk::{keygen_pk, keygen_vk},
    utils::fs::gen_srs,
};
use halo2_base::{
    Context,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::arithmetic::Field;
use rand::rngs::OsRng;
use std::env::var;

fn some_algorithm_in_zk<F: ScalarField>(ctx: &mut Context<F>, x: F) {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // first we load a private input `x` (let's not worry about public inputs for now)
    let x = ctx.load_witness(x);

    // create a Gate chip that contains methods for basic arithmetic operations
    let gate = GateChip::<F>::default();

    // now we can perform arithmetic operations almost like a normal program using halo2-lib API functions
    // square x
    let x_sq = gate.mul(ctx, x, x);

    // x^2 + 72
    let c = F::from(72);
    // the implicit type of most variables is an "Existing" assigned value
    // a known constant is a separate type that we specify by `Constant(c)`:
    let _ = gate.add(ctx, x_sq, Constant(c));

    // here is a more optimal way to compute x^2 + 72 using the lower level `assign_region` API:
    let val = *x.value() * x.value() + c;
    let _val_assigned =
        ctx.assign_region_last([Constant(c), Existing(x), Existing(x), Witness(val)], [0]);
    // the `[0]` tells us to turn on a vertical `a + b * c = d` gate at row position 0.
    // this imposes the constraint c + x * x = val
}

fn main() {
    env_logger::init();

    // run mock prover
    mock();

    // uncomment below to run actual prover:
    // prove();
}

// The functions below are generic scaffolding functions and do not need to be changed.

/// Creates a circuit and runs the Halo2 `MockProver` on it. Will print out errors if the circuit does not pass.
///
/// This requires an environment variable `DEGREE` to be set, which limits the number of rows of the circuit to 2<sup>DEGREE</sup>.
pub fn mock() {
    // we initiate a "thread builder" in mockprover mode. This is what keeps track of the execution trace of our program and the ZK constraints so we can do some post-processing optimization after witness generation
    let mut builder = GateThreadBuilder::mock();
    // builder.main(phase) gets a default "main" thread for the given phase. For most purposes we only need to think about phase 0
    // we use a random input
    // while `some_algorithm_in_zk` was written generically for any field `F`, in practice we use the scalar field of the BN254 curve because that's what the proving system backend uses
    some_algorithm_in_zk(builder.main(0), Fr::random(OsRng));

    // now `builder` contains the execution trace, and we are ready to actually create the circuit
    let k = var("DEGREE").unwrap_or_else(|_| "18".to_string()).parse().unwrap();
    // minimum rows is the number of rows used for blinding factors. This depends on the circuit itself, but we can guess the number and change it if something breaks (default 9 usually works)
    let minimum_rows = var("MINIMUM_ROWS").unwrap_or_else(|_| "9".to_string()).parse().unwrap();
    // auto-tune circuit
    builder.config(k, Some(minimum_rows));
    // create circuit
    let circuit = GateCircuitBuilder::mock(builder);

    let time = start_timer!(|| "Mock prover");
    // we don't have any public inputs for now
    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied();
    end_timer!(time);
    println!("Mock prover passed!");
}

/// Creates a circuit and runs the full Halo2 proving process on it.
/// Will time the generation of verify key & proving key. It will then run the prover on the given circuit.
/// Finally the verifier will verify the proof. The verifier will panic if the proof is invalid.
///
/// Warning: This may be memory and compute intensive.
pub fn prove() {
    let k = var("DEGREE").unwrap_or_else(|_| "18".to_string()).parse().unwrap();
    let minimum_rows = var("MINIMUM_ROWS").unwrap_or_else(|_| "9".to_string()).parse().unwrap();
    // much the same process as [`mock()`], but we need to create a separate circuit for the key generation stage and the proving stage (in production they are done separately)

    // in keygen mode, the private variables are all not used
    let mut builder = GateThreadBuilder::keygen();
    some_algorithm_in_zk(builder.main(0), Fr::zero()); // the input value doesn't matter here for keygen
    builder.config(k, Some(minimum_rows));

    let circuit = GateCircuitBuilder::keygen(builder);

    // generates a random universal trusted setup and write to file for later re-use. This is NOT for production. In production a trusted setup must be created from a multi-party computation
    let params = gen_srs(k as u32);
    let vk_time = start_timer!(|| "Generating verifying key");
    let vk = keygen_vk(&params, &circuit).expect("vk generation failed");
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "Generating proving key");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk generation failed");
    end_timer!(pk_time);
    // The MAIN DIFFERENCE in this setup is that after pk generation, the shape of the circuit is set in stone. We should not auto-configure the circuit anymore. Instead, we get the circuit shape and store it:
    let break_points = circuit.break_points.take();

    let input = Fr::random(OsRng); // mocking with a random input
    let pf_time = start_timer!(|| "Creating KZG proof using SHPLONK multi-open scheme");
    // we time creation of the builder because this is the witness generation stage and can only
    // be done after the private inputs are known
    let mut builder = GateThreadBuilder::prover();
    some_algorithm_in_zk(builder.main(0), input);
    // once again, we have a pre-determined way to break up the builder "threads" into an optimal
    // circuit shape, so we create the prover circuit from this information (`break_points`)
    let circuit = GateCircuitBuilder::prover(builder, break_points);

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
    .expect("proof generation failed");
    let proof = transcript.finalize();
    end_timer!(pf_time);

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_time = start_timer!(|| "verify");
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&params, pk.get_vk(), strategy, &[&[]], &mut transcript)
    .unwrap();
    end_timer!(verify_time);

    println!("Congratulations! Your ZK proof is valid!");
}
