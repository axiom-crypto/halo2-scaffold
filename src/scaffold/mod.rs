//! This module contains helper functions to handle some common setup to convert the `some_algorithm_in_zk` function in the examples into a Halo2 circuit.
//! These functions are not quite general enough to place into `halo2-lib` yet, so they are just some internal helpers for this crate only for now.
//! We recommend not reading this module on first (or second) pass.
// use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
        flex_gate::MultiPhaseThreadBreakPoints,
    },
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{verify_proof, Circuit, ProvingKey, VerifyingKey},
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
    utils::fs::gen_srs,
    AssignedValue,
};
use serde::de::DeserializeOwned;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{gen_snark_shplonk, read_snark, PoseidonTranscript},
    read_pk, CircuitExt, NativeLoader,
};
use std::{
    env::var,
    fs::{self, File},
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
    time::Instant,
};

use self::cmd::{Cli, SnarkCmd};

pub mod cmd;

pub struct CircuitScaffold<T, Fn> {
    f: Fn,
    private_inputs: T,
}

pub fn run<T: DeserializeOwned>(
    f: impl FnOnce(&mut BaseCircuitBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>),
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
    run_on_inputs(f, cli, private_inputs)
}

pub fn run_on_inputs<T: DeserializeOwned>(
    f: impl FnOnce(&mut BaseCircuitBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    cli: Cli,
    private_inputs: T,
) {
    let precircuit = CircuitScaffold { f, private_inputs };

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
            let circuit = precircuit.create_circuit(CircuitBuilderStage::Keygen, None, &params);
            let pk = gen_pk(&params, &circuit, None);
            let c_params = circuit.params();
            let break_points = circuit.break_points();
            let mut pinning_file = File::create(&pinning_path)
                .unwrap_or_else(|_| panic!("Could not create file at {pinning_path:?}"));
            serde_json::to_writer(&mut pinning_file, &(c_params, break_points))
                .expect("Could not write pinning file");
            let mut pk_file = BufWriter::new(
                File::create(&pk_path)
                    .unwrap_or_else(|_| panic!("Could not create file at {pk_path:?}")),
            );
            pk.write(&mut pk_file, SerdeFormat::RawBytes).expect("Failed to write proving key");
            println!("Proving key written to: {pk_path:?}");

            let vk_path = data_path.join(PathBuf::from(format!("{name}.vk")));
            let f = File::create(&vk_path)
                .unwrap_or_else(|_| panic!("Could not create file at {vk_path:?}"));
            let mut writer = BufWriter::new(f);
            pk.get_vk()
                .write(&mut writer, SerdeFormat::RawBytes)
                .expect("writing vkey should not fail");
            println!("Verifying key written to: {vk_path:?}");
        }
        SnarkCmd::Prove => {
            let pinning_path = config_path.join(PathBuf::from(format!("{name}.json")));
            let mut pinning_file = File::open(&pinning_path)
                .unwrap_or_else(|_| panic!("Could not read file at {pinning_path:?}"));
            let pinning: (BaseCircuitParams, MultiPhaseThreadBreakPoints) =
                serde_json::from_reader(&mut pinning_file).expect("Could not read pinning file");
            let circuit =
                precircuit.create_circuit(CircuitBuilderStage::Prover, Some(pinning), &params);
            let pk_path = data_path.join(PathBuf::from(format!("{name}.pk")));
            let pk = custom_read_pk(pk_path, &circuit);
            let snark_path = data_path.join(PathBuf::from(format!("{name}.snark")));
            if snark_path.exists() {
                fs::remove_file(&snark_path).unwrap();
            }
            let start = Instant::now();
            gen_snark_shplonk(&params, &pk, circuit, Some(&snark_path));
            let prover_time = start.elapsed();
            println!("Proving time: {:?}", prover_time);
            println!("Snark written to: {snark_path:?}");
        }
        SnarkCmd::Verify => {
            let vk_path = data_path.join(PathBuf::from(format!("{name}.vk")));
            let mut circuit = precircuit.create_circuit(CircuitBuilderStage::Keygen, None, &params);
            let vk = custom_read_vk(vk_path, &circuit);
            let snark_path = data_path.join(PathBuf::from(format!("{name}.snark")));
            let snark = read_snark(&snark_path)
                .unwrap_or_else(|e| panic!("Snark not found at {snark_path:?}. {e:?}"));

            let verifier_params = params.verifier_params();
            let strategy = SingleStrategy::new(&params);
            let mut transcript =
                PoseidonTranscript::<NativeLoader, &[u8]>::new::<0>(&snark.proof[..]);
            let instance = &snark.instances[0][..];
            let start = Instant::now();
            verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<'_, Bn256>,
                _,
                _,
                SingleStrategy<'_, Bn256>,
            >(verifier_params, &vk, strategy, &[&[instance]], &mut transcript)
            .unwrap();
            let verification_time = start.elapsed();
            println!("Snark verified successfully in {:?}", verification_time);
            circuit.clear();
        }
    }
}

fn custom_read_pk<C, P>(fname: P, circuit: &C) -> ProvingKey<G1Affine>
where
    C: Circuit<Fr>,
    P: AsRef<Path>,
{
    read_pk::<C>(fname.as_ref(), circuit.params())
        .unwrap_or_else(|e| panic!("Failed to open file: {:?}: {e:?}", fname.as_ref()))
}

fn custom_read_vk<C, P>(fname: P, circuit: &C) -> VerifyingKey<G1Affine>
where
    C: Circuit<Fr>,
    P: AsRef<Path>,
{
    let f = File::open(&fname)
        .unwrap_or_else(|e| panic!("Failed to open file: {:?}: {e:?}", fname.as_ref()));
    let mut bufreader = BufReader::new(f);
    VerifyingKey::read::<_, C>(&mut bufreader, SerdeFormat::RawBytes, circuit.params())
        .expect("Could not read vkey")
}

impl<T, Fn> CircuitScaffold<T, Fn>
where
    Fn: FnOnce(&mut BaseCircuitBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>),
{
    /// Creates a Halo2 circuit from the given function.
    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<(BaseCircuitParams, MultiPhaseThreadBreakPoints)>,
        params: &ParamsKZG<Bn256>,
    ) -> BaseCircuitBuilder<Fr> {
        let mut builder = BaseCircuitBuilder::from_stage(stage);
        if let Some((params, break_points)) = pinning {
            builder.set_params(params);
            builder.set_break_points(break_points);
        } else {
            let k = params.k() as usize;
            // we use env var `LOOKUP_BITS` to determine whether to use `GateThreadBuilder` or `RangeCircuitBuilder`. The difference is that the latter creates a lookup table with 2^LOOKUP_BITS rows, while the former does not.
            let lookup_bits: Option<usize> = var("LOOKUP_BITS")
                .map(|str| {
                    let lookup_bits = str.parse::<usize>().unwrap();
                    // we use a lookup table with 2^LOOKUP_BITS rows. Due to blinding factors, we need a little more than 2^LOOKUP_BITS rows total in our circuit
                    assert!(lookup_bits < k, "LOOKUP_BITS needs to be less than DEGREE");
                    lookup_bits
                })
                .ok();
            // we initiate a "thread builder". This is what keeps track of the execution trace of our program. If not in proving mode, it also keeps track of the ZK constraints.
            builder.set_k(k);
            if let Some(lookup_bits) = lookup_bits {
                builder.set_lookup_bits(lookup_bits);
            }
            builder.set_instance_columns(1);
        };

        // builder.main(phase) gets a default "main" thread for the given phase. For most purposes we only need to think about phase 0
        // we need a 64-bit number as input in this case
        // while `some_algorithm_in_zk` was written generically for any field `F`, in practice we use the scalar field of the BN254 curve because that's what the proving system backend uses
        let mut assigned_instances = vec![];
        (self.f)(&mut builder, self.private_inputs, &mut assigned_instances);
        if !assigned_instances.is_empty() {
            assert_eq!(builder.assigned_instances.len(), 1, "num_instance_columns != 1");
            builder.assigned_instances[0] = assigned_instances;
        }

        if !stage.witness_gen_only() {
            // now `builder` contains the execution trace, and we are ready to actually create the circuit
            // minimum rows is the number of rows used for blinding factors. This depends on the circuit itself, but we can guess the number and change it if something breaks (default 9 usually works)
            let minimum_rows =
                var("MINIMUM_ROWS").unwrap_or_else(|_| "20".to_string()).parse().unwrap();
            builder.calculate_params(Some(minimum_rows));
        }

        builder
    }
}
