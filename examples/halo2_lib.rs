use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    Context, ContextParams,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng;

#[derive(Clone, Default)]
struct MyCircuit {
    x: Value<Fr>,
}

impl Circuit<Fr> for MyCircuit {
    type Config = FlexGateConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner; // we will always use SimpleFloorPlanner

    fn without_witnesses(&self) -> Self {
        // set `x` to `Value::unknown()` for verifying key and proving key generation, which are steps that do not depend on the witnesses
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // you can always set strategy to Vertical and context_id = 0 for now
        // we need to know `degree` where the final circuit will have `2^degree` rows
        // `advice` is the number of advice columns
        // `fixed` is the number of fixed columns
        let degree: usize = std::env::var("DEGREE")
            .unwrap_or_else(|_| panic!("set DEGREE env variable to usize"))
            .parse()
            .unwrap_or_else(|_| panic!("set DEGREE env variable to usize"));
        FlexGateConfig::configure(meta, GateStrategy::Vertical, &[1], 1, 0, degree)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // this is where witness generation happens

        // halo2 allows you to specify computations and constraints in "regions": you specify what columns to use, and row positions are relative to the region
        // it will then try to re-arrange the regions vertically to pack in as much as possible - this is called the layouter

        // we find the layouter to slow down performance, so we prefer to do everything in a single region and you as the circuit designer can either manually or automatically optimize the grid layout
        let mut first_pass = true;
        layouter.assign_region(
            || "put a name if you want",
            |region| {
                // because of the layouter's intent to re-arrange regions, it always calls this closure TWICE: the first time to figure out the "shape" of the region, the second time to actually do the computations
                // doing things twice is slow, so we skip this step. ONLY do this if you are using a single region!
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                // to do our own "auto-"assignment of cells and to keep track of how many cells are used, etc, we put everything into a `Context` struct: this is basically the `region` + helper stats
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: config.max_rows,
                        num_context_ids: 1,
                        fixed_columns: config.constants.clone(),
                    },
                );

                // now to the actual computation

                // first we load a private input `x` (let's not worry about public inputs for now)
                let x = config.assign_witnesses(&mut ctx, vec![self.x]).pop().unwrap();

                // square x
                let x_sq = config.mul(&mut ctx, Existing(&x), Existing(&x));

                // x^2 + 72
                let c = Fr::from(72);
                let _ = config.add(&mut ctx, Existing(&x_sq), Constant(c));

                // here is a more optimal way to compute x^2 + 72 using our API:
                let val = x.value().map(|x| *x * x + c);
                let _ = config.assign_region_last(
                    &mut ctx,
                    vec![Constant(c), Existing(&x), Existing(&x), Witness(val)],
                    vec![(0, None)],
                );
                // the `vec![(0, None)]` tells us to turn on a vertical `a + b * c = d` gate at row position 0. Ignore the `None` for now - it's just always there

                Ok(())
            },
        )?;

        // post processing if you want
        Ok(())
    }
}

fn main() {
    let k = 5; // this is the log_2(rows) you specify
    std::env::set_var("DEGREE", k.to_string());
    // we generate a universal trusted setup of our own for testing
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);

    // just to emphasize that for vk, pk we don't need to know the value of `x`
    let circuit = MyCircuit { x: Value::unknown() };
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    // now we generate an actual proof for a random input x
    let circuit = MyCircuit { x: Value::known(Fr::random(OsRng)) };

    let pf_time = start_timer!(|| "Creating proof");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
        _,
    >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
    .expect("prover should not fail");
    let proof = transcript.finalize();
    end_timer!(pf_time);

    // verify the proof to make sure everything is ok
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
    .is_ok());
}
