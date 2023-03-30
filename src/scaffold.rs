//! This module contains helper functions to handle some common setup to convert the `some_algorithm_in_zk` function in the examples into a Halo2 circuit.
//! These functions are not quite general enough to place into `halo2-lib` yet, so they are just some internal helpers for this crate only for now.
//! We recommend not reading this module on first (or second) pass.
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{
        builder::{GateCircuitBuilder, GateThreadBuilder, RangeCircuitBuilder},
        flex_gate::FlexGateConfig,
        range::RangeConfig,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Column, ConstraintSystem,
            Error, Instance,
        },
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    utils::{fs::gen_srs, ScalarField},
    AssignedValue, Context,
};
use rand::rngs::OsRng;
use std::env::var;

///! The functions below are generic scaffolding functions to create circuits with 'halo2-lib'

/// Creates a circuit and runs the Halo2 `MockProver` on it. Will print out errors if the circuit does not pass.
///
/// This requires an environment variable `DEGREE` to be set, which limits the number of rows of the circuit to 2<sup>DEGREE</sup>.
pub fn mock<T>(
    f: impl FnOnce(&mut Context<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    private_inputs: T,
) {
    let k = var("DEGREE").unwrap_or_else(|_| "18".to_string()).parse().unwrap();
    // we use env var `LOOKUP_BITS` to determine whether to use `GateThreadBuilder` or `RangeCircuitBuilder`. The difference is that the latter creates a lookup table with 2^LOOKUP_BITS rows, while the former does not.
    let lookup_bits: Option<usize> = var("LOOKUP_BITS")
        .map(|str| {
            let lookup_bits = str.parse().unwrap();
            // we use a lookup table with 2^LOOKUP_BITS rows. Due to blinding factors, we need a little more than 2^LOOKUP_BITS rows total in our circuit
            assert!(lookup_bits < k, "LOOKUP_BITS needs to be less than DEGREE");
            lookup_bits
        })
        .ok();

    // we initiate a "thread builder" in mockprover mode. This is what keeps track of the execution trace of our program and the ZK constraints so we can do some post-processing optimization after witness generation
    let mut builder = GateThreadBuilder::mock();
    // builder.main(phase) gets a default "main" thread for the given phase. For most purposes we only need to think about phase 0
    // we need a 64-bit number as input in this case
    // while `some_algorithm_in_zk` was written generically for any field `F`, in practice we use the scalar field of the BN254 curve because that's what the proving system backend uses
    let mut assigned_instances = vec![];
    f(builder.main(0), private_inputs, &mut assigned_instances);

    // now `builder` contains the execution trace, and we are ready to actually create the circuit
    // minimum rows is the number of rows used for blinding factors. This depends on the circuit itself, but we can guess the number and change it if something breaks (default 9 usually works)
    let minimum_rows = var("MINIMUM_ROWS").unwrap_or_else(|_| "9".to_string()).parse().unwrap();
    // auto-tune circuit
    builder.config(k, Some(minimum_rows));

    let public_io: Vec<Fr> = assigned_instances.iter().map(|v| *v.value()).collect();
    let time = start_timer!(|| "Mock prover");
    if lookup_bits.is_some() {
        // create circuit
        let circuit = RangeWithInstanceCircuitBuilder {
            circuit: RangeCircuitBuilder::mock(builder),
            assigned_instances,
        };

        // we don't have any public inputs for now
        MockProver::run(k as u32, &circuit, vec![public_io]).unwrap().assert_satisfied();
    } else {
        // create circuit
        let circuit = GateWithInstanceCircuitBuilder {
            circuit: GateCircuitBuilder::mock(builder),
            assigned_instances,
        };

        // we don't have any public inputs for now
        MockProver::run(k as u32, &circuit, vec![public_io]).unwrap().assert_satisfied();
    }
    end_timer!(time);
    println!("Mock prover passed!");
}

/// Creates a circuit and runs the full Halo2 proving process on it.
/// Will time the generation of verify key & proving key. It will then run the prover on the given circuit.
/// Finally the verifier will verify the proof. The verifier will panic if the proof is invalid.
///
/// Warning: This may be memory and compute intensive.
///
/// * `private_inputs` are the private inputs you want to prove a computation on.
/// * `dummy_inputs` are some dummy private inputs, in the correct format for your circuit, that should be used just for proving key generation. They can be the same as `private_inputs` for testing, but in production the proving key is generated only once, so `dummy_inputs` is usually different from `private_inputs` and it is best to test your circuit using different inputs to make sure you don't have any missed logic.
pub fn prove<T>(
    f: impl Fn(&mut Context<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    private_inputs: T,
    dummy_inputs: T,
) {
    let k = var("DEGREE").unwrap_or_else(|_| "18".to_string()).parse().unwrap();
    // we use env var `LOOKUP_BITS` to determine whether to use `GateThreadBuilder` or `RangeCircuitBuilder`. The difference is that the latter creates a lookup table with 2^LOOKUP_BITS rows, while the former does not.
    let lookup_bits: Option<usize> = var("LOOKUP_BITS")
        .map(|str| {
            let lookup_bits = str.parse().unwrap();
            // we use a lookup table with 2^LOOKUP_BITS rows. Due to blinding factors, we need a little more than 2^LOOKUP_BITS rows total in our circuit
            assert!(lookup_bits < k, "LOOKUP_BITS needs to be less than DEGREE");
            lookup_bits
        })
        .ok();
    let minimum_rows = var("MINIMUM_ROWS").unwrap_or_else(|_| "9".to_string()).parse().unwrap();
    // much the same process as [`mock()`], but we need to create a separate circuit for the key generation stage and the proving stage (in production they are done separately)

    // in keygen mode, the private variables are all not used
    let mut builder = GateThreadBuilder::keygen();
    let mut assigned_instances = vec![];
    f(builder.main(0), dummy_inputs, &mut assigned_instances); // the input value doesn't matter here for keygen
    builder.config(k, Some(minimum_rows));

    // generates a random universal trusted setup and write to file for later re-use. This is NOT for production. In production a trusted setup must be created from a multi-party computation
    let params = gen_srs(k as u32);
    let vk;
    let pk;
    let break_points;

    // rust types does not allow dynamic dispatch of different circuit types, so here we are
    if lookup_bits.is_some() {
        let circuit = RangeWithInstanceCircuitBuilder {
            circuit: RangeCircuitBuilder::keygen(builder),
            assigned_instances,
        };

        let vk_time = start_timer!(|| "Generating verifying key");
        vk = keygen_vk(&params, &circuit).expect("vk generation failed");
        end_timer!(vk_time);
        let pk_time = start_timer!(|| "Generating proving key");
        pk = keygen_pk(&params, vk, &circuit).expect("pk generation failed");
        end_timer!(pk_time);
        // The MAIN DIFFERENCE in this setup is that after pk generation, the shape of the circuit is set in stone. We should not auto-configure the circuit anymore. Instead, we get the circuit shape and store it:
        break_points = circuit.circuit.0.break_points.take();
    } else {
        let circuit = GateWithInstanceCircuitBuilder {
            circuit: GateCircuitBuilder::keygen(builder),
            assigned_instances,
        };

        let vk_time = start_timer!(|| "Generating verifying key");
        vk = keygen_vk(&params, &circuit).expect("vk generation failed");
        end_timer!(vk_time);
        let pk_time = start_timer!(|| "Generating proving key");
        pk = keygen_pk(&params, vk, &circuit).expect("pk generation failed");
        end_timer!(pk_time);
        // The MAIN DIFFERENCE in this setup is that after pk generation, the shape of the circuit is set in stone. We should not auto-configure the circuit anymore. Instead, we get the circuit shape and store it:
        break_points = circuit.circuit.break_points.take();
    }

    let pf_time = start_timer!(|| "Creating KZG proof using SHPLONK multi-open scheme");
    // we time creation of the builder because this is the witness generation stage and can only
    // be done after the private inputs are known
    let mut builder = GateThreadBuilder::prover();
    let mut assigned_instances = vec![];
    f(builder.main(0), private_inputs, &mut assigned_instances);
    let public_io: Vec<Fr> = assigned_instances.iter().map(|v| *v.value()).collect();
    // once again, we have a pre-determined way to break up the builder "threads" into an optimal
    // circuit shape, so we create the prover circuit from this information (`break_points`)
    let proof = if lookup_bits.is_some() {
        let circuit = RangeWithInstanceCircuitBuilder {
            circuit: RangeCircuitBuilder::prover(builder, break_points),
            assigned_instances,
        };
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[&public_io]], OsRng, &mut transcript)
        .expect("proof generation failed");
        transcript.finalize()
    } else {
        let circuit = GateWithInstanceCircuitBuilder {
            circuit: GateCircuitBuilder::prover(builder, break_points),
            assigned_instances,
        };
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[&public_io]], OsRng, &mut transcript)
        .expect("proof generation failed");
        transcript.finalize()
    };
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
    >(&params, pk.get_vk(), strategy, &[&[&public_io]], &mut transcript)
    .unwrap();
    end_timer!(verify_time);

    println!("Congratulations! Your ZK proof is valid!");
}

#[derive(Clone, Debug)]
pub struct GateWithInstanceConfig<F: ScalarField> {
    pub gate: FlexGateConfig<F>,
    pub instance: Column<Instance>,
}

/// This is an extension of [`GateCircuitBuilder`] that adds support for public instances (aka public inputs+outputs)
///
/// The intended design is that a [`GateThreadBuilder`] is populated and then produces some assigned instances, which are supplied as `assigned_instances` to this struct.
/// The [`Circuit`] implementation for this struct will then expose these instances and constrain them using the Halo2 API.
pub struct GateWithInstanceCircuitBuilder<F: ScalarField> {
    pub circuit: GateCircuitBuilder<F>,
    pub assigned_instances: Vec<AssignedValue<F>>,
}

impl<F: ScalarField> Circuit<F> for GateWithInstanceCircuitBuilder<F> {
    type Config = GateWithInstanceConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let gate = GateCircuitBuilder::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        GateWithInstanceConfig { gate, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // we later `take` the builder, so we need to save this value
        let witness_gen_only = self.circuit.builder.borrow().witness_gen_only();
        let assigned_advices = self.circuit.sub_synthesize(&config.gate, &[], &[], &mut layouter);

        if !witness_gen_only {
            // expose public instances
            let mut layouter = layouter.namespace(|| "expose");
            for (i, instance) in self.assigned_instances.iter().enumerate() {
                let cell = instance.cell.unwrap();
                let (cell, _) = assigned_advices
                    .get(&(cell.context_id, cell.offset))
                    .expect("instance not assigned");
                layouter.constrain_instance(*cell, config.instance, i);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RangeWithInstanceConfig<F: ScalarField> {
    pub range: RangeConfig<F>,
    pub instance: Column<Instance>,
}

/// This is an extension of [`RangeCircuitBuilder`] that adds support for public instances (aka public inputs+outputs)
///
/// The intended design is that a [`GateThreadBuilder`] is populated and then produces some assigned instances, which are supplied as `assigned_instances` to this struct.
/// The [`Circuit`] implementation for this struct will then expose these instances and constrain them using the Halo2 API.
#[derive(Clone, Debug)]
pub struct RangeWithInstanceCircuitBuilder<F: ScalarField> {
    pub circuit: RangeCircuitBuilder<F>,
    pub assigned_instances: Vec<AssignedValue<F>>,
}

impl<F: ScalarField> Circuit<F> for RangeWithInstanceCircuitBuilder<F> {
    type Config = RangeWithInstanceConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let range = RangeCircuitBuilder::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        RangeWithInstanceConfig { range, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // copied from RangeCircuitBuilder::synthesize but with extra logic to expose public instances
        let range = config.range;
        let circuit = &self.circuit.0;
        range.load_lookup_table(&mut layouter).expect("load lookup table should not fail");
        // we later `take` the builder, so we need to save this value
        let witness_gen_only = circuit.builder.borrow().witness_gen_only();
        let assigned_advices = circuit.sub_synthesize(
            &range.gate,
            &range.lookup_advice,
            &range.q_lookup,
            &mut layouter,
        );

        if !witness_gen_only {
            // expose public instances
            let mut layouter = layouter.namespace(|| "expose");
            for (i, instance) in self.assigned_instances.iter().enumerate() {
                let cell = instance.cell.unwrap();
                let (cell, _) = assigned_advices
                    .get(&(cell.context_id, cell.offset))
                    .expect("instance not assigned");
                layouter.constrain_instance(*cell, config.instance, i);
            }
        }
        Ok(())
    }
}
