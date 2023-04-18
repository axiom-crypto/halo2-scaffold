# Halo2 Scaffolding

This repository is intended to provide a playground for you to easily start writing a ZK circuit using the Halo2 proving stack.

## Setup

Install rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone this repo:

```bash
git clone https://github.com/axiom-crypto/halo2-scaffold.git
cd halo2-scaffold
```

## Quick start with `halo2-lib`

To write your first ZK circuit, copy [`examples/halo2_lib.rs`](examples/halo2_lib.rs) to a new file in `examples` directory. Now you can fill in the `some_function_in_zk` function with your desired computation.

We provide some examples of how to write these functions:

- [`examples/halo2_lib.rs`](examples/halo2_lib.rs): Takes in an input `x` and computes `x**2 + 27` in several different ways.
- [`examples/range.rs`](examples/range.rs): Takes in an input `x` and checks if `x` is in `[0, 2**64)`.
- [`examples/poseidon.rs`](examples/poseidon.rs): Takes in two inputs `x, y` and computes the Poseidon hash of `[x, y]`. We recommend skipping this example on first pass unless you explicitly need to use the Poseidon hash function for something.

These examples use the [halo2-lib](https://github.com/axiom-crypto/halo2-lib/tree/axiom-dev-0301) API, which is a frontend API we wrote to aid in ZK circuit development on top of the original `halo2_proofs` API. This API is designed to be easier to use for ZK beginners and improve development velocity for all ZK developers.

For a walkthrough of these examples, see [this doc](https://docs.axiom.xyz/~/changes/ztIYKznQAmn202AIDFuO/zero-knowledge-proofs/getting-started-with-halo2).

To explore all the functions available in the halo2-lib API, see this [list](https://docs.axiom.xyz/~/changes/ztIYKznQAmn202AIDFuO/zero-knowledge-proofs/getting-started-with-halo2#available-api-functions).

Below we go over the available ZK commands that can be run on your circuit. They work on each of the examples above, replacing the name `halo2_lib` below with `<Example Name>`.

### Mock Prover

After writing your circuit, run the mock prover using

```bash
cargo run --example halo2_lib -- --name halo2_lib -k <DEGREE> mock # for example, DEGREE=8
```

where `--name` can be used to specify any name for your circuit. By default, the program will try to read in the input as a JSON from [`data/halo2_lib.in`](data/halo2_lib.in). A different input path can be specified with option `--input filename.in` which is expected to be located at `data/filename.in`.

The `MockProver` does not run the cryptographic prover on your circuit, but instead directly checks if constraints are satisfied. This is useful for testing purposes, and runs faster than the actual prover.

Here `DEGREE` is a variable you specify to set the circuit to have `2^DEGREE` number of rows. The halo2-lib API will automatically allocate columns for the optimal circuit that fits within the specified number of rows. See [here](https://docs.axiom.xyz/zero-knowledge-proofs/getting-started-with-halo2#cost-modeling) for a discussion of how to think about the row vs. column tradeoff in a Halo2 circuit. _Note:_ The last ~9 rows of a circuit are reserved for the proof system (blinding factors to ensure zero-knowledge).

If you want to see the statistics for what is actually being auto-configured in the circuit, you can run

```bash
RUST_LOG=info cargo run --example halo2_lib -- --name halo2_lib -k <DEGREE> mock
```

### Key generation

To generate a random universal trusted setup (for testing only!) and the proving and verifying keys for your circuit, run

```bash
cargo run --example halo2_lib -- --name halo2_lib -k <DEGREE> --input halo2_lib.0.in keygen
```

For technical reasons (to be removed in the future), keygen still requires an input file of the correct format. However keygen is only done once per circuit, so it is best practice to use a different input than the input you want to test with.

This will generate a proving key `data/halo2_lib.pk` and a verifying key `data/halo2_lib.vk`. It will also generate a file `configs/halo2_lib.json` which describes (and pins down) the configuration of the circuit. This configuration file is later read by the prover.

### Proof generation

After you have generated the proving and verifying keys, you can generate a proof for your circuit using

```bash
cargo run --example halo2_lib -- --name halo2_lib -k <DEGREE> prove
```

This creates a SNARK proof, stored as a binary file `data/halo2_lib.snark`, using the inputs read (by default) from `data/halo2_lib.in`. You can specify a different input file with the option `--input filename.in`, which would look for a file at `data/filename.in`.

Using the same proving key, you can generate proofs for the same ZK circuit on _different_ inputs using this command.

### Verifying a proof

You can verify the proof generated above using

```bash
cargo run --example halo2_lib -- --name halo2_lib -k <DEGREE> verify
```

## Range checks

It is often necessary to use functions that involve checking that a certain field element has a certain number of bits. While there are ways to do this by computing the full bit decomposition, it is more efficient in Halo2 to use a lookup table. We provide a `RangeChip` that has this functionality built in (together with various other functions: see the trait [`RangeInstructions`](https://axiom-crypto.github.io/halo2-lib/halo2_base/gates/range/trait.RangeInstructions.html) which `RangeChip` implements).

You can find an example of how to use `RangeChip` in [`range.rs`](examples/range.rs). To run this example, run

```bash
LOOKUP_BITS=8 cargo run --example range -- --name range -k <DEGREE> <COMMAND>
```

where `<COMMAND>` can be `mock`, `keygen`, `prove`, or `verify`.
You can change `LOOKUP_BITS` to any number less than `DEGREE`. Internally, we use the lookup table to check that a number is in `[0, 2**LOOKUP_BITS)`. However in the external `RangeInstructions::range_check` function, we have some additional logic that allows you to check that a number is in `[0, 2**bits)` for _any_ number of bits `bits`. For example, in the `range.rs` example, we check that an input is in `[0, 2**64)`. This works regardless of what `LOOKUP_BITS` is set to.

## Using the vanilla Halo2 API

**Note:** If you just want to get started writing a circuit, we recommend skipping this section and focusing on the section [above](#quick-start-with-halo2-lib) instead.

For documentation on the vanilla Halo2 API, see the [halo2 book](https://zcash.github.io/halo2/index.html) as well as the [rustdocs](https://axiom-crypto.github.io/halo2/halo2_proofs/).

To see the basic scaffolding needed to begin writing a circuit using the raw Halo2 API, see the examples in the [`circuits`](src/circuits/) directory. We recommend looking at the examples in this order:

- [OR gate](src/circuits/or.rs): creates a "custom" OR gate and then writes a circuit to compute logical OR of two bits.
- [Standard PLONK](src/circuits/standard_plonk.rs): creates a circuit that implements the standard PLONK gate.
- [Is Zero](src/circuits/is_zero.rs): creates a circuit that performs the computation `x -> x == 0 ? 1 : 0`.

To run the mock prover on for example the `or.rs` circuit for testing purposes, run

```bash
cargo test -- --nocapture test_or
```

where `--nocapture` tells rust to display any stdout outputs (by default tests omit stdout).
This performs witness generation on the circuit and checks that the constraints you imposed are satisfied. This does _not_ run the actual cryptographic operations behind a ZK proof. As a result, the mock prover is much faster than the actual prover, and should be used first for all debugging purposes.

You can replace `test_or` with `test_standard_plonk` or `test_is_zero_zero` or `test_is_zero_random` to run the mock prover on the other circuits.

### Running the actual prover

For those curious, we also provide an example showing how to run the actual prover for the [`standard_plonk.rs`](src/circuits/standard_plonk.rs) circuit.
To run the actual prover this circuit to mimic a production setup and to get benchmarks, run

```bash
cargo run --release --example standard_plonk
```

This runs the [`examples/standard_plonk.rs`](examples/standard_plonk.rs) code with full optimization. The tradeoff is that compile times can be
slow. For nearly as fast performance with better compile times, run

```bash
cargo run --profile=local --example standard_plonk
```
