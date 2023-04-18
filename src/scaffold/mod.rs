//! This module contains helper functions to handle some common setup to convert the `some_algorithm_in_zk` function in the examples into a Halo2 circuit.
//! These functions are not quite general enough to place into `halo2-lib` yet, so they are just some internal helpers for this crate only for now.
//! We recommend not reading this module on first (or second) pass.
// use ark_std::{end_timer, start_timer};
use axiom_eth::util::{
    circuit::{PinnableCircuit, PreCircuit},
    AggregationConfigPinning, Halo2ConfigPinning,
};
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateCircuitBuilder, GateThreadBuilder,
            MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
        },
        flex_gate::FlexGateConfig,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{
            verify_proof, Circuit, Column, ConstraintSystem, Error, Instance, ProvingKey,
            VerifyingKey,
        },
        poly::{
            commitment::{Params, ParamsProver},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::VerifierSHPLONK,
                strategy::SingleStrategy,
            },
        },
        SerdeFormat,
    },
    utils::{fs::gen_srs, ScalarField},
    AssignedValue, Context,
};
use serde::de::DeserializeOwned;
use snark_verifier_sdk::{
    halo2::{
        aggregation::{RangeWithInstanceCircuitBuilder, RangeWithInstanceConfig},
        gen_snark_shplonk, read_snark, PoseidonTranscript,
    },
    read_pk, CircuitExt, NativeLoader,
};
use std::{
    env::{set_var, var},
    fs::{self, File},
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
};

use self::cmd::{Cli, SnarkCmd};

pub mod cmd;
///! The functions below are generic scaffolding functions to create circuits with 'halo2-lib'

pub struct CircuitScaffold<T, Fn>
where
    Fn: FnOnce(&mut Context<Fr>, T, &mut Vec<AssignedValue<Fr>>),
{
    f: Fn,
    private_inputs: T,
}

pub fn run<T: DeserializeOwned>(
    f: impl FnOnce(&mut Context<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    cli: Cli,
) {
    let name = cli.name;
    let input_path = PathBuf::from("data")
        .join(cli.input_path.unwrap_or_else(|| PathBuf::from(format!("{name}.in"))));
    let private_inputs: T = serde_json::from_reader(
        File::open(&input_path)
            .unwrap_or_else(|e| panic!("Input file not found at {input_path:?}. {e:?}")),
    )
    .expect("Input file should be a valid JSON file");
    let k = cli.degree;

    let config_path = cli.config_path.unwrap_or_else(|| PathBuf::from("configs"));
    let data_path = cli.data_path.unwrap_or_else(|| PathBuf::from("data"));
    fs::create_dir_all(&config_path).unwrap();
    fs::create_dir_all(&data_path).unwrap();

    let params = gen_srs(k);
    println!("Universal trusted setup (unsafe!) available at: params/kzg_bn254_{k}.srs");
    match cli.command {
        SnarkCmd::Mock => {
            let precircuit = CircuitScaffold { f, private_inputs };
            let circuit = precircuit.create_circuit(CircuitBuilderStage::Mock, None, &params);
            MockProver::run(k, &circuit, circuit.instances()).unwrap().assert_satisfied();
        }
        SnarkCmd::Keygen => {
            let precircuit = CircuitScaffold { f, private_inputs };
            let pk_path = data_path.join(PathBuf::from(format!("{name}.pk")));
            if pk_path.exists() {
                fs::remove_file(&pk_path).unwrap();
            }
            let pinning_path = config_path.join(PathBuf::from(format!("{name}.json")));
            let pk = precircuit.create_pk(&params, &pk_path, pinning_path);
            println!("Proving key written to: {pk_path:?}");

            let vk_path = data_path.join(PathBuf::from(format!("{name}.vk")));
            let f = File::create(&vk_path).unwrap();
            let mut writer = BufWriter::new(f);
            pk.get_vk()
                .write(&mut writer, SerdeFormat::RawBytes)
                .expect("writing vkey should not fail");
            println!("Verifying key written to: {vk_path:?}");
        }
        SnarkCmd::Prove => {
            let precircuit = CircuitScaffold { f, private_inputs };
            let pinning_path = config_path.join(PathBuf::from(format!("{name}.json")));
            let pinning = AggregationConfigPinning::from_path(pinning_path);
            pinning.set_var();
            let circuit =
                precircuit.create_circuit(CircuitBuilderStage::Prover, Some(pinning), &params);
            let pk_path = data_path.join(PathBuf::from(format!("{name}.pk")));
            let pk = custom_read_pk(pk_path, &circuit);
            let snark_path = data_path.join(PathBuf::from(format!("{name}.snark")));
            if snark_path.exists() {
                fs::remove_file(&snark_path).unwrap();
            }
            gen_snark_shplonk(&params, &pk, circuit, Some(&snark_path));
            println!("Snark written to: {snark_path:?}");
        }
        SnarkCmd::Verify => {
            let precircuit = CircuitScaffold { f, private_inputs };
            let vk_path = data_path.join(PathBuf::from(format!("{name}.vk")));
            let circuit = precircuit.create_circuit(CircuitBuilderStage::Keygen, None, &params);
            let vk = custom_read_vk(vk_path, &circuit);
            let snark_path = data_path.join(PathBuf::from(format!("{name}.snark")));
            let snark = read_snark(&snark_path)
                .unwrap_or_else(|e| panic!("Snark not found at {snark_path:?}. {e:?}"));

            let verifier_params = params.verifier_params();
            let strategy = SingleStrategy::new(&params);
            let mut transcript =
                PoseidonTranscript::<NativeLoader, &[u8]>::new::<0>(&snark.proof[..]);
            let instance = &snark.instances[0][..];
            verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<'_, Bn256>,
                _,
                _,
                SingleStrategy<'_, Bn256>,
            >(verifier_params, &vk, strategy, &[&[instance]], &mut transcript)
            .unwrap();
            println!("Snark verified successfully!");
        }
    }
}

fn custom_read_pk<C, P>(fname: P, _: &C) -> ProvingKey<G1Affine>
where
    C: Circuit<Fr>,
    P: AsRef<Path>,
{
    read_pk::<C>(fname.as_ref())
        .unwrap_or_else(|e| panic!("Failed to open file: {:?}: {e:?}", fname.as_ref()))
}

fn custom_read_vk<C, P>(fname: P, _: &C) -> VerifyingKey<G1Affine>
where
    C: Circuit<Fr>,
    P: AsRef<Path>,
{
    let f = File::open(&fname)
        .unwrap_or_else(|e| panic!("Failed to open file: {:?}: {e:?}", fname.as_ref()));
    let mut bufreader = BufReader::new(f);
    VerifyingKey::read::<_, C>(&mut bufreader, SerdeFormat::RawBytes).expect("Could not read vkey")
}

impl<T, Fn> PreCircuit for CircuitScaffold<T, Fn>
where
    Fn: FnOnce(&mut Context<Fr>, T, &mut Vec<AssignedValue<Fr>>),
{
    type Pinning = AggregationConfigPinning;

    /// Creates a Halo2 circuit from the given function.
    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        // we initiate a "thread builder". This is what keeps track of the execution trace of our program. If not in proving mode, it also keeps track of the ZK constraints.
        let mut builder = match stage {
            CircuitBuilderStage::Prover => GateThreadBuilder::new(true),
            _ => GateThreadBuilder::new(false),
        };
        let k = params.k() as usize;
        // we use env var `LOOKUP_BITS` to determine whether to use `GateThreadBuilder` or `RangeCircuitBuilder`. The difference is that the latter creates a lookup table with 2^LOOKUP_BITS rows, while the former does not.
        let lookup_bits: usize = var("LOOKUP_BITS")
            .map(|str| {
                let lookup_bits = str.parse().unwrap();
                // we use a lookup table with 2^LOOKUP_BITS rows. Due to blinding factors, we need a little more than 2^LOOKUP_BITS rows total in our circuit
                assert!(lookup_bits < k, "LOOKUP_BITS needs to be less than DEGREE");
                lookup_bits
            })
            .unwrap_or(0);
        // set `LOOKUP_BITS` to '0' if it is not set; this is just a technicality to re-use some other code
        set_var("LOOKUP_BITS", lookup_bits.to_string());
        // builder.main(phase) gets a default "main" thread for the given phase. For most purposes we only need to think about phase 0
        // we need a 64-bit number as input in this case
        // while `some_algorithm_in_zk` was written generically for any field `F`, in practice we use the scalar field of the BN254 curve because that's what the proving system backend uses
        let mut assigned_instances = vec![];
        (self.f)(builder.main(0), self.private_inputs, &mut assigned_instances);

        // now `builder` contains the execution trace, and we are ready to actually create the circuit
        // minimum rows is the number of rows used for blinding factors. This depends on the circuit itself, but we can guess the number and change it if something breaks (default 9 usually works)
        let minimum_rows = var("MINIMUM_ROWS").unwrap_or_else(|_| "9".to_string()).parse().unwrap();
        // auto-tune circuit
        match stage {
            CircuitBuilderStage::Prover => {}
            _ => {
                builder.config(k, Some(minimum_rows));
            }
        };

        if lookup_bits != 0 {
            let circuit = match stage {
                CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(
                    builder,
                    pinning.expect("Circuit pinning not found").break_points(),
                ),
                CircuitBuilderStage::Keygen => RangeCircuitBuilder::keygen(builder),
                CircuitBuilderStage::Mock => RangeCircuitBuilder::mock(builder),
            };
            ScaffoldCircuitBuilder::Range(RangeWithInstanceCircuitBuilder::new(
                circuit,
                assigned_instances,
            ))
        } else {
            let circuit = match stage {
                CircuitBuilderStage::Prover => GateCircuitBuilder::prover(
                    builder,
                    pinning.expect("Circuit pinning not found").break_points(),
                ),
                CircuitBuilderStage::Keygen => GateCircuitBuilder::keygen(builder),
                CircuitBuilderStage::Mock => GateCircuitBuilder::mock(builder),
            };
            ScaffoldCircuitBuilder::Gate(GateWithInstanceCircuitBuilder {
                circuit,
                assigned_instances,
            })
        }
    }
}

#[derive(Clone, Debug)]
pub enum ScaffoldConfig<F: ScalarField> {
    Gate(GateWithInstanceConfig<F>),
    Range(RangeWithInstanceConfig<F>),
}

pub enum ScaffoldCircuitBuilder<F: ScalarField> {
    Gate(GateWithInstanceCircuitBuilder<F>),
    Range(RangeWithInstanceCircuitBuilder<F>),
}

impl<F: ScalarField> Circuit<F> for ScaffoldCircuitBuilder<F> {
    type Config = ScaffoldConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let lookup_bits: usize =
            var("LOOKUP_BITS").unwrap_or_else(|_| "0".to_string()).parse().unwrap();
        if lookup_bits != 0 {
            ScaffoldConfig::Range(RangeWithInstanceCircuitBuilder::configure(meta))
        } else {
            ScaffoldConfig::Gate(GateWithInstanceCircuitBuilder::configure(meta))
        }
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        match (self, config) {
            (ScaffoldCircuitBuilder::Gate(circuit), ScaffoldConfig::Gate(config)) => {
                circuit.synthesize(config, layouter)
            }
            (ScaffoldCircuitBuilder::Range(circuit), ScaffoldConfig::Range(config)) => {
                circuit.synthesize(config, layouter)
            }
            _ => unreachable!(),
        }
    }
}

impl<F: ScalarField> CircuitExt<F> for ScaffoldCircuitBuilder<F> {
    fn num_instance(&self) -> Vec<usize> {
        match self {
            ScaffoldCircuitBuilder::Gate(circuit) => vec![circuit.assigned_instances.len()],
            ScaffoldCircuitBuilder::Range(circuit) => vec![circuit.assigned_instances.len()],
        }
    }

    fn instances(&self) -> Vec<Vec<F>> {
        match self {
            ScaffoldCircuitBuilder::Gate(circuit) => {
                vec![circuit.assigned_instances.iter().map(|v| *v.value()).collect()]
            }
            ScaffoldCircuitBuilder::Range(circuit) => circuit.instances(),
        }
    }
}

impl<F: ScalarField> PinnableCircuit<F> for ScaffoldCircuitBuilder<F> {
    type Pinning = AggregationConfigPinning;

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        match self {
            ScaffoldCircuitBuilder::Gate(circuit) => circuit.circuit.break_points.borrow().clone(),
            ScaffoldCircuitBuilder::Range(circuit) => {
                circuit.circuit.0.break_points.borrow().clone()
            }
        }
    }
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
