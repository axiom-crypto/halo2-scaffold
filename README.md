# Halo2 Scaffolding

`my_circuit.rs` contains basic demonstration of how to create a halo2 circuit using the (PSE fork of) the halo2_proofs API.
It shows creation of a "custom gate" that implements the standard PLONK gate.

To run the mock prover for testing purposes,

```
cargo test -- --nocapture test_standard_plonk
```

where `--nocapture` tells rust to display any stdout outputs (by default tests omit stdout).

To run the actual prover for `my_circuit` to get benchmarks,

```
cargo run --release
```

This runs the `main.rs` code.

---

`examples/halo2_lib.rs` gives an example of how to use halo2-lib/halo2_base to write circuits using Axiom's aided frontend. Run it using

```
cargo run --example halo2_lib --release
```
