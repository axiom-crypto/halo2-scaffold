//! Example of running the actual Halo2 prover and verifier on the Standard PLONK circuit.
//!
//! Note: Do not read this on first pass of this repository.
use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    arithmetic::Field,
    circuit::Value,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
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
use halo2_scaffold::circuits::standard_plonk::StandardPlonk;
use rand::rngs::OsRng;

fn main() {
    let k = 5; // this is the log_2(rows) you specify

    // we generate a universal trusted setup of our own for testing
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);

    // just to emphasize that for vk, pk we don't need to know the value of `x`
    let circuit = StandardPlonk { x: Value::unknown() };
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    // now we generate an actual proof for a random input x
    let circuit = StandardPlonk { x: Value::known(Fr::random(OsRng)) };

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
