# Halo2 Scaffolding

This repository is intended to provide a playground for you to easily start writing a ZK circuit using the Halo2 proving stack.

## Getting started

Install rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone this repo:

```bash
git clone https://github.com/axiom-crypto/halo2-scaffold.git
cd halo2-scaffold
git switch halo2-lib-v0.3
```

## Learning Halo2

To see the basic scaffolding needed to begin writing a circuit and examples of how to use the Halo2 API, see [`my_circuit.rs`](src/my_circuit.rs). This contains a basic demonstration of how to create a halo2 circuit using the (PSE fork of) the halo2_proofs API. It shows creation of a "custom gate" that implements the standard PLONK gate.

To run the mock prover on this circuit for testing purposes, run

```bash
cargo test -- --nocapture test_standard_plonk
```

where `--nocapture` tells rust to display any stdout outputs (by default tests omit stdout).
This performs witness generation on the circuit and checks that the constraints you imposed are satisfied. This does run the actual cryptographic operations behind a ZK proof. As a result, the mock prover is much faster than the actual prover, and should be used first for all debugging purposes.

To run the actual prover for `my_circuit` to mimic a production setup and to get benchmarks, run

```bash
cargo run --release
```

This runs the [`main.rs`](src/main.rs) code with full optimization. The tradeoff is that compile times can be
slow. For nearly as fast performance with better compile times, run

```bash
cargo run --profile=local
```

## Using the halo2-lib API

We wrote [halo2-lib](https://github.com/axiom-crypto/halo2-lib/tree/axiom-dev-0301) to provide another
layer of abstraction on top of the halo2_proofs API. This API is designed to be easier to use for
ZK beginners and improve development velocity for all ZK developers. See
[`examples/halo2_lib.rs`](examples/halo2_lib.rs) for an example of how to use halo2-lib/halo2-base to write circuits using Axiom's aided frontend.

We have abstracted away much of the original Halo2 API: now to write the circuit you just need to fill in the `some_function_in_zk` function.

To explore all the functions available in the halo2-lib API, see the [halo2-lib documentation](https://axiom-crypto.github.io/halo2-lib/halo2_base/index.html).

After writing your circuit, run it using

```bash
DEGREE=<k> cargo run --example halo2_lib --release
```

or

```bash
DEGREE=<k> cargo run --example halo2_lib --profile=local
```

Here `DEGREE` is an environmental variable you specify to set the circuit to have `2^DEGREE` number of rows. The halo2-lib API will automatically allocate columns for the optimal circuit that fits within the specified number of rows. See [here](https://docs.axiom.xyz/zero-knowledge-proofs/getting-started-with-halo2#cost-modeling) for a discussion of how to think about the row vs. column tradeoff in a Halo2 circuit.

If you want to see the statistics for what is actually being auto-configured in the circuit, you can run

```bash
RUST_LOG=info DEGREE=<k> cargo run --example halo2_lib --profile=local
```
