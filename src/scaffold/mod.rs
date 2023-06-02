//! This module contains helper functions to handle some common setup to convert the `some_algorithm_in_zk` function in the examples into a Halo2 circuit.
//! These functions are not quite general enough to place into `halo2-lib` yet, so they are just some internal helpers for this crate only for now.
//! We recommend not reading this module on first (or second) pass.
// use ark_std::{end_timer, start_timer};
use axiom_eth::{
    keccak::FnSynthesize,
    util::{
        circuit::{PinnableCircuit, PreCircuit},
        AggregationConfigPinning, Halo2ConfigPinning,
    },
};
use halo2_base::{
    gates::builder::{
        CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
        RangeWithInstanceCircuitBuilder, RangeWithInstanceConfig,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{verify_proof, Circuit, ConstraintSystem, Error, ProvingKey, VerifyingKey},
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
    halo2::{gen_snark_shplonk, read_snark, PoseidonTranscript},
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

pub struct CircuitScaffold<T, Fn> {
    f: Fn,
    private_inputs: T,
}

pub fn run<T: DeserializeOwned>(
    f: impl FnOnce(&mut Context<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    cli: Cli,
) {
    run_builder(|builder, inp, public| f(builder.main(0), inp, public), cli)
}

pub fn run_builder<T: DeserializeOwned>(
    f: impl FnOnce(&mut GateThreadBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    cli: Cli,
) {
    let name = &cli.name;
    let input_path = PathBuf::from("data")
        .join(cli.input_path.clone().unwrap_or_else(|| PathBuf::from(format!("{name}.in"))));
    let private_inputs: T = serde_json::from_reader(
        File::open(&input_path)
            .unwrap_or_else(|e| panic!("Input file not found at {input_path:?}. {e:?}")),
    )
    .expect("Input file should be a valid JSON file");
    run_builder_on_inputs(f, cli, private_inputs)
}

pub fn run_builder_on_inputs<T: DeserializeOwned>(
    f: impl FnOnce(&mut GateThreadBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    cli: Cli,
    private_inputs: T,
) {
    let precircuit = pre_run_builder_on_inputs(f, private_inputs);
    run_cli(precircuit, cli);
}

pub fn pre_run_builder_on_inputs<T>(
    f: impl FnOnce(&mut GateThreadBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    private_inputs: T,
) -> CircuitScaffold<T, impl FnOnce(&mut GateThreadBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>)> {
    CircuitScaffold { f, private_inputs }
}

pub use eth::*;
mod eth {
    use std::{
        cell::RefCell,
        env::{set_var, var},
        fs::File,
        marker::PhantomData,
        path::PathBuf,
    };

    use axiom_eth::{
        keccak::{FixedLenRLCs, KeccakChip, VarLenRLCs},
        rlp::{builder::RlcThreadBuilder, RlpChip},
        util::{
            circuit::{PinnableCircuit, PreCircuit},
            EthConfigPinning,
        },
        EthChip, EthCircuitBuilder, ETH_LOOKUP_BITS,
    };
    use halo2_base::{
        gates::builder::{CircuitBuilderStage, GateThreadBuilder},
        halo2_proofs::{
            halo2curves::bn256::{Bn256, Fr},
            poly::{commitment::Params, kzg::commitment::ParamsKZG},
        },
        safe_types::RangeChip,
        AssignedValue, Context,
    };
    use serde::de::DeserializeOwned;

    use super::{cmd::Cli, run_cli};

    pub struct EthScaffold<T, FN, F1> {
        f: FN,
        private_inputs: T,
        _f1: PhantomData<F1>,
    }

    impl<T, FN, F1> PreCircuit for EthScaffold<T, FN, F1>
    where
        FN: FnOnce(
            &mut GateThreadBuilder<Fr>,
            &EthChip<Fr>,
            &mut KeccakChip<Fr>,
            T,
            &mut Vec<AssignedValue<Fr>>,
        ) -> F1,
        F1: FnOnce(&mut Context<Fr>, &mut Context<Fr>, &EthChip<Fr>) + Clone,
    {
        type Pinning = EthConfigPinning;

        fn create_circuit(
            self,
            stage: CircuitBuilderStage,
            pinning: Option<Self::Pinning>,
            params: &ParamsKZG<Bn256>,
        ) -> impl PinnableCircuit<Fr> {
            let mut builder = RlcThreadBuilder::new(stage == CircuitBuilderStage::Prover);
            let lookup_bits: usize =
                var("LOOKUP_BITS").unwrap_or_else(|_| ETH_LOOKUP_BITS.to_string()).parse().unwrap();
            set_var("LOOKUP_BITS", lookup_bits.to_string());
            let range = RangeChip::default(lookup_bits);
            let chip = EthChip::new(RlpChip::new(&range, None), None);
            let mut keccak = KeccakChip::default();

            let mut assigned_instances = vec![];
            let f_phase1 = (self.f)(
                &mut builder.gate_builder,
                &chip,
                &mut keccak,
                self.private_inputs,
                &mut assigned_instances,
            );
            let break_points = pinning.map(|p| p.break_points);
            let circuit = EthCircuitBuilder::new(
                assigned_instances,
                builder,
                RefCell::new(keccak),
                range,
                break_points,
                |builder: &mut RlcThreadBuilder<Fr>,
                 rlp: RlpChip<Fr>,
                 keccak_rlcs: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {
                    let chip = EthChip::new(rlp, Some(keccak_rlcs));
                    let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
                    (f_phase1)(ctx_gate, ctx_rlc, &chip);
                    if ctx_gate.advice.is_empty() {
                        builder.gate_builder.threads[1].pop();
                    }
                },
            );
            if stage != CircuitBuilderStage::Prover {
                circuit.config(params.k() as usize, Some(109));
            }
            circuit
        }
    }

    pub fn run_eth<T, FN, F1>(f: FN, cli: Cli)
    where
        T: DeserializeOwned,
        FN: FnOnce(
            &mut Context<Fr>,
            &EthChip<Fr>,
            &mut KeccakChip<Fr>,
            T,
            &mut Vec<AssignedValue<Fr>>,
        ) -> F1,
        F1: FnOnce(&mut Context<Fr>, &mut Context<Fr>, &EthChip<Fr>) + Clone,
    {
        run_eth_builder(
            |builder, chip, keccak, inp, public| f(builder.main(0), chip, keccak, inp, public),
            cli,
        )
    }

    pub fn run_eth_builder<T, FN, F1>(f: FN, cli: Cli)
    where
        T: DeserializeOwned,
        FN: FnOnce(
            &mut GateThreadBuilder<Fr>,
            &EthChip<Fr>,
            &mut KeccakChip<Fr>,
            T,
            &mut Vec<AssignedValue<Fr>>,
        ) -> F1,
        F1: FnOnce(&mut Context<Fr>, &mut Context<Fr>, &EthChip<Fr>) + Clone,
    {
        let name = &cli.name;
        let input_path = PathBuf::from("data")
            .join(cli.input_path.clone().unwrap_or_else(|| PathBuf::from(format!("{name}.in"))));
        let private_inputs: T = serde_json::from_reader(
            File::open(&input_path)
                .unwrap_or_else(|e| panic!("Input file not found at {input_path:?}. {e:?}")),
        )
        .expect("Input file should be a valid JSON file");
        run_eth_builder_on_inputs(f, cli, private_inputs)
    }

    pub fn run_eth_builder_on_inputs<T, FN, F1>(f: FN, cli: Cli, private_inputs: T)
    where
        T: DeserializeOwned,
        FN: FnOnce(
            &mut GateThreadBuilder<Fr>,
            &EthChip<Fr>,
            &mut KeccakChip<Fr>,
            T,
            &mut Vec<AssignedValue<Fr>>,
        ) -> F1,
        F1: FnOnce(&mut Context<Fr>, &mut Context<Fr>, &EthChip<Fr>) + Clone,
    {
        let precircuit = EthScaffold { f, private_inputs, _f1: PhantomData };
        run_cli(precircuit, cli);
    }
}

pub fn run_cli<P: PreCircuit>(precircuit: P, cli: Cli) {
    let name = cli.name;
    let k = cli.degree;

    let config_path = cli.config_path.unwrap_or_else(|| PathBuf::from("configs"));
    let data_path = cli.data_path.unwrap_or_else(|| PathBuf::from("data"));
    fs::create_dir_all(&config_path).unwrap();
    fs::create_dir_all(&data_path).unwrap();

    let params = gen_srs(k);
    println!("Universal trusted setup (unsafe!) available at: params/kzg_bn254_{k}.srs");
    match cli.command {
        SnarkCmd::Mock => {
            let circuit = precircuit.create_circuit(CircuitBuilderStage::Mock, None, &params);
            MockProver::run(k, &circuit, circuit.instances()).unwrap().assert_satisfied();
        }
        SnarkCmd::Keygen => {
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
            let pinning_path = config_path.join(PathBuf::from(format!("{name}.json")));
            let pinning = P::Pinning::from_path(pinning_path);
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
    Fn: FnOnce(&mut GateThreadBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>),
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
        (self.f)(&mut builder, self.private_inputs, &mut assigned_instances);

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

        let circuit = match stage {
            CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(
                builder,
                pinning.expect("Circuit pinning not found").break_points(),
            ),
            CircuitBuilderStage::Keygen => RangeCircuitBuilder::keygen(builder),
            CircuitBuilderStage::Mock => RangeCircuitBuilder::mock(builder),
        };
        ScaffoldCircuitBuilder(RangeWithInstanceCircuitBuilder::new(circuit, assigned_instances))
    }
}

pub struct ScaffoldCircuitBuilder<F: ScalarField>(RangeWithInstanceCircuitBuilder<F>);

impl<F: ScalarField> Circuit<F> for ScaffoldCircuitBuilder<F> {
    type Config = RangeWithInstanceConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        RangeWithInstanceCircuitBuilder::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        self.0.synthesize(config, layouter)
    }
}

impl<F: ScalarField> CircuitExt<F> for ScaffoldCircuitBuilder<F> {
    fn num_instance(&self) -> Vec<usize> {
        vec![self.0.assigned_instances.len()]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        self.0.instances()
    }
}

impl<F: ScalarField> PinnableCircuit<F> for ScaffoldCircuitBuilder<F> {
    type Pinning = AggregationConfigPinning;

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.0.circuit.0.break_points.borrow().clone()
    }
}
