use clap::Parser;
use ethers_core::utils::hex::FromHex;
use halo2_base::{gates::GateChip, utils::ScalarField, AssignedValue, Context, safe_types::GateInstructions, QuantumCell::Constant};
use halo2_scaffold::scaffold::{cmd::Cli, run};
use poseidon::PoseidonChip;
use serde::{Deserialize, Serialize};

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

const PROOF_SZ: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub inputs: [String; PROOF_SZ*2+2], // two field elements, but as strings for easier deserialization
}

fn verify_merkle_proof<F: ScalarField>(
    ctx: &mut Context<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let mut proof_vec = vec![];
    for input in inp.inputs {
        if input.starts_with("[") {
            let sz = input.len();
            // println!("{:?}", input[1..sz]);
            // let a: Vec<&str> = input[1..sz-1].split(", ").collect();
            // println!("{:?}", a);
            let numbers: Vec<u8> = input[1..sz-1].split(", ").map(|x|u8::from_str_radix(x, 10).unwrap()).collect();
            proof_vec.push(ctx.load_witness(F::from_bytes_le(numbers.as_slice())))
        }
        else {
            proof_vec.push(ctx.load_witness(F::from_str_vartime(&input).unwrap()));
        }
    }

    let tree_root = proof_vec[0];
    proof_vec.remove(0);
    make_public.push(tree_root);

    let gate = GateChip::<F>::default();
    let mut poseidon = PoseidonChip::<F, T, RATE>::new(ctx, R_F, R_P).unwrap();
    let mut cur_hash = proof_vec[0];
    make_public.push(cur_hash);
    proof_vec.remove(0);
    let sz = proof_vec.len();
    for i in 0..sz/2 {
        let node = proof_vec[i*2];
        let b0 = proof_vec[i*2+1];
        let b1 = gate.xor(ctx, b0, Constant(F::from(1)));
        let f_ch = gate.mul(ctx, b1, cur_hash);
        let f_nd = gate.mul(ctx, b0, node);
        let first = gate.add(ctx, f_ch, f_nd);
        let s_ch = gate.mul(ctx, b0, cur_hash);
        let s_nd = gate.mul(ctx, b1, node);
        let snd = gate.add(ctx, s_ch, s_nd);
        println!("frst: {:?}, snd: {:?}", first.value(), snd.value());
        poseidon.clear();
        poseidon.update(&[first, snd]);
        cur_hash = poseidon.squeeze(ctx, &gate).unwrap();
        println!("cur_hash: {:?}", cur_hash.value());
    }
    make_public.push(cur_hash);
    gate.is_equal(ctx, cur_hash, tree_root);
    println!("root: {:?}, poseidon(x_1, ..., x_n): {:?}", tree_root.value(), cur_hash.value());
}


fn gen_merkle_root<F: ScalarField>(
    ctx: &mut Context<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let mut proof_vec = vec![];
    for input in inp.inputs {
        proof_vec.push(ctx.load_witness(F::from_str_vartime(&input).unwrap()));
    }

    // let tree_root = proof_vec[0];
    // proof_vec.remove(0);
    // make_public.push(tree_root);

    let gate = GateChip::<F>::default();
    let mut poseidon = PoseidonChip::<F, T, RATE>::new(ctx, R_F, R_P).unwrap();
    let mut sz = 8;
    for i in 0..4 {
        let mut proof_vec_new = vec![];
        for j in 0..sz/2 {
            poseidon.clear();
            poseidon.update(&[proof_vec[j*2], proof_vec[j*2+1]]);
            let cur_hash = poseidon.squeeze(ctx, &gate).unwrap();
            let vecc = cur_hash.value().to_bytes_le();
            println!("i: {:?}, j: {:?}, hash: {:?}", i, j, vecc );
            println!("i: {:?}, j: {:?}, hash: {:?}", i, j, cur_hash.value() );
            proof_vec_new.push(cur_hash);
        }
        sz /= 2;
        proof_vec = proof_vec_new;
    }
    // let mut cur_hash = proof_vec[0];
    // make_public.push(cur_hash);
    // proof_vec.remove(0);
    // for node in proof_vec {
    //     poseidon.update(&[cur_hash, node]);
    //     cur_hash = poseidon.squeeze(ctx, &gate).unwrap();
    // }
    // make_public.push(cur_hash);
    // gate.is_equal(ctx, cur_hash, tree_root);
    // println!("root: {:?}, poseidon(x_1, ..., x_n): {:?}", tree_root.value(), cur_hash.value());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    run(verify_merkle_proof, args);
}


/*


    "inputs": [
        "0x111339f32b5390a1bda6c9dd93436140964691bd64d9789a81afa6abb7dc499d",
        "3", 
        "2",
        "1",
        "0x305df2f9f9f1c0b591427aa9fd8ff8b8b8ad8a16953065fca066cb6a69deff53",
        "1",
        "0x2d311b4dc1f798b1a8aa862ac5f792d0e4a27690c2bfc1378c0ef3b71cdd3e2b",
        "0"
    ]

i: 0, j: 0, hash: [83, 255, 222, 105, 106, 203, 102, 160, 252, 101, 48, 149, 22, 138, 173, 184, 184, 248, 143, 253, 169, 122, 66, 145, 181, 192, 241, 249, 249, 242, 93, 48]
i: 0, j: 0, hash: 0x305df2f9f9f1c0b591427aa9fd8ff8b8b8ad8a16953065fca066cb6a69deff53
i: 0, j: 1, hash: [254, 5, 9, 90, 3, 185, 152, 7, 226, 243, 37, 98, 27, 142, 244, 121, 38, 83, 255, 12, 97, 140, 185, 118, 13, 39, 102, 196, 62, 215, 6, 14]
i: 0, j: 1, hash: 0x0e06d73ec466270d76b98c610cff532679f48e1b6225f3e20798b9035a0905fe
i: 0, j: 2, hash: [160, 231, 238, 69, 244, 80, 215, 48, 250, 178, 104, 226, 118, 104, 118, 40, 40, 153, 250, 124, 93, 65, 86, 45, 176, 10, 201, 46, 207, 55, 165, 4]
i: 0, j: 2, hash: 0x04a537cf2ec90ab02d56415d7cfa992828766876e268b2fa30d750f445eee7a0
i: 0, j: 3, hash: [49, 147, 115, 76, 73, 68, 31, 204, 15, 5, 27, 146, 187, 229, 70, 143, 63, 146, 46, 43, 177, 203, 97, 135, 59, 196, 226, 187, 13, 109, 189, 41]
i: 0, j: 3, hash: 0x29bd6d0dbbe2c43b8761cbb12b2e923f8f46e5bb921b050fcc1f44494c739331
i: 1, j: 0, hash: [148, 33, 125, 213, 56, 138, 50, 79, 185, 153, 255, 245, 196, 84, 14, 250, 107, 133, 154, 22, 24, 220, 49, 21, 197, 255, 199, 33, 216, 235, 1, 44]
i: 1, j: 0, hash: 0x2c01ebd821c7ffc51531dc18169a856bfa0e54c4f5ff99b94f328a38d57d2194
i: 1, j: 1, hash: [156, 216, 84, 72, 226, 111, 38, 73, 105, 66, 64, 100, 181, 163, 122, 36, 14, 150, 255, 206, 91, 131, 187, 43, 41, 83, 83, 245, 89, 189, 134, 10]
i: 1, j: 1, hash: 0x0a86bd59f55353292bbb835bceff960e247aa3b56440426949266fe24854d89c
i: 2, j: 0, hash: [5, 57, 239, 39, 54, 150, 109, 89, 198, 162, 78, 207, 167, 95, 36, 114, 240, 48, 139, 37, 80, 215, 242, 141, 126, 138, 234, 44, 253, 85, 49, 46]
i: 2, j: 0, hash: 0x2e3155fd2cea8a7e8df2d750258b30f072245fa7cf4ea2c6596d963627ef3905
*/