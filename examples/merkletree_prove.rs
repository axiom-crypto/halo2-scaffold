#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

use std::{process::exit, io::Write};

use clap::Parser;
use halo2_base::{gates::{GateChip, circuit::builder::BaseCircuitBuilder}, utils::BigPrimeField, AssignedValue, poseidon::hasher::PoseidonHasher};
use halo2_scaffold::scaffold::{cmd::Cli, run};
use serde::{Serialize, Serializer};
use snark_verifier_sdk::halo2::OptimizedPoseidonSpec;

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

const INP_SZ: usize = 1048576;
const PROOF_SZ: usize = 21;

pub fn serialize_array<S, T>(array: &[T], serializer: S) -> Result<S::Ok, S::Error>
where S: Serializer, T: Serialize {
	array.serialize(serializer)
}

#[macro_export]
macro_rules! serde_array { ($m:ident, $n:expr) => {
	pub mod $m {
		use std::{ptr};
		use serde::{Deserialize, Deserializer, de};
		pub use $crate::serialize_array as serialize;
		use super::*;

		pub fn deserialize<'de, D, T>(deserializer: D) -> Result<[T; $n], D::Error>
		where D: Deserializer<'de>, T: Deserialize<'de> + 'de {
			let slice: Vec<T> = Deserialize::deserialize(deserializer).unwrap();
			if slice.len() != $n {
				return Err(de::Error::custom("input slice has wrong length"));
			}
			unsafe {
				let mut result: [T; $n] = std::mem::MaybeUninit::uninit().assume_init();
				println!("HAHA");
                for (src, dst) in slice.into_iter().zip(&mut result[..]) {
					ptr::write(dst, src);
				}
				Ok(result)
			}
		}
	}
}}

serde_array!(a64, 64);
serde_array!(a32769, 32769);
serde_array!(a65537, 65537);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    // #[serde(with = "a65537")]
    // pub inputs: [String; INP_SZ+1],
}


fn gen_merkle_root_proof<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    inp: CircuitInput,
    _make_public: &mut Vec<AssignedValue<F>>,
) {
    let ctx = builder.main(0);
    let mut prove_id: usize = 3;
    let mut proof_vec = vec![];
    for i in 0..INP_SZ {
        let s_input = i.to_string();
        let input = s_input.as_str();
        proof_vec.push(ctx.load_witness(F::from_str_vartime(&input).unwrap()));
    }
    // for input in inp.inputs.split_last().unwrap().1 {
    //     proof_vec.push(ctx.load_witness(F::from_str_vartime(&input).unwrap()));
    // }

    // let tree_root = proof_vec[0];
    // proof_vec.remove(0);
    // make_public.push(tree_root);
    
    let gate = GateChip::<F>::default();
    let mut poseidon = PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());
    let mut sz = INP_SZ;
    println!("\"{:?}\",", proof_vec[prove_id].value().to_bytes_le());
    println!("\"{:?}\",", proof_vec[prove_id^1].value().to_bytes_le());
    if prove_id % 2 == 0 {
        println!("\"0\",");
    }
    else {
        println!("\"1\",");
    }
    for i in 1..PROOF_SZ {
        prove_id /= 2;
        for j in 0..sz/2 {
            poseidon.clear();
            poseidon.initialize_consts(ctx, &gate);
            let cur_hash = poseidon.hash_fix_len_array(ctx, &gate, &[proof_vec[j*2], proof_vec[j*2+1]]);
            ctx.advice.clear();
            ctx.selector.clear();
            let mut cpManager = ctx.copy_manager.lock().unwrap();
            cpManager.advice_equalities.clear();
            cpManager.assigned_advices.clear();
            cpManager.assigned_constants.clear();
            cpManager.constant_equalities.clear();
            if j == prove_id^1 {
                println!("\"{:?}\",", cur_hash.value().to_bytes_le());
                std::io::stdout().flush().unwrap();
            }
            proof_vec[j] = cur_hash;
            // proof_vec_new.push(cur_hash);
        }
        if i+1 != PROOF_SZ {
            if prove_id % 2 == 0 {
                println!("\"0\",");
            }
            else {
                println!("\"1\",");
            }
        }
        sz /= 2;
    }
    // print root
    println!("\"{:?}\"", proof_vec[0].value().to_bytes_le());
    println!("OMG");
    exit(0);
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    run(gen_merkle_root_proof, args);
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

tree build from [1, 2, 3, 4, 5, 6, 7, 8]

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