use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

#[derive(Clone, Copy, Debug)]
pub struct OrConfig {
    witness: Column<Advice>,
    selector: Selector,
}

// Our circuit is going to look like:
// | witness | selector |
// | a0      | s0       |
// | a1      | s1       |
// | a2      | s2       |
// ...
// with gate:
// s_i * (a_i + a_{i+1} - a_i * a_{i+1} - a_{i+2}) = 0 for all i

impl OrConfig {
    // it is standard practice to define everything where numbers are in a generic prime field `F` (`FieldExt` are the traits of a prime field)
    // `meta` is provided by the halo2 backend, it is the api for specifying PLONKish arithmetization grid shape + storing circuit constraints in polynomial form
    pub fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        // create a single witness column
        let witness = meta.advice_column();
        let selector = meta.selector();

        // specify the columns that you may want to impose equality constraints on cells for (this may include fixed columns)
        meta.enable_equality(witness);

        // we create a single OR gate
        meta.create_gate("OR gate", |meta| {
            // this gate will be applied AT EVERY ROW
            // the relative offsets are specified using `Rotation`

            // we `query` for the `Expression` corresponding to the cell entry in a particular column at a relative row offset
            let a = meta.query_advice(witness, Rotation::cur());
            let b = meta.query_advice(witness, Rotation(1)); // or Rotation::next()
            let out = meta.query_advice(witness, Rotation(2)); // or Rotation::next()
            let sel = meta.query_selector(selector);

            // specify all polynomial expressions that we require to equal zero
            // `Expression` is basically an abstract container for the polynomial corresponding to a column; in particular it can't implement `Copy` so we need to clone it to pass rust ownership rules
            vec![sel * (a.clone() + b.clone() - a * b - out)]
        });

        Self { witness, selector }
    }
}

// we use the config to make a circuit:
// a circuit struct just holds the public/private inputs of a particular input for the circuit to compute
// slightly counterintuitive since the ZKCircuit is only created once, but it is then run multiple times with different inputs
// you should think that during actual ZKCircuit creation, these are just placeholders for the actual inputs
#[derive(Clone, Default)]
pub struct OrCircuit<F: FieldExt> {
    // let's say our circuit wants to compute a | b
    // ASSUME that the values of a,b are both in {0,1}
    pub a: Value<F>, // Value is a wrapper for rust `Option` with some arithmetic operator overloading
    pub b: Value<F>,
}

// now we implement the halo2 `Circuit` trait for our struct to actually make it a circuit
impl<F: FieldExt> Circuit<F> for OrCircuit<F> {
    type Config = OrConfig; // our earlier config
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        // you don't actually need to implement this if you don't want to
        unimplemented!()
        // the intention is you return a version of the circuit inputs where all private inputs are `Value::unknown()` to emphasize they shouldn't be known at circuit creation time
        /*
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
        }
        */
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        OrConfig::configure::<F>(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Or circuit, only using 1 region",
            |mut region| {
                // for performance, it is better to avoid the ? operator; see https://github.com/rust-lang/rust/issues/37939

                // self.a, self.b are the two private inputs
                // we need to first load them into our circuit
                // | row | witness | selector |
                // | 0   | a       |          |
                // | 1   | b       |          |

                // The API calls witness cells "advice"
                // For mysterious reasons (weird rust trait issues), this function takes closures
                let a = region.assign_advice(
                    || "a | annotation just for debugging",
                    config.witness,
                    0,
                    || self.a,
                )?;
                let b = region.assign_advice(
                    || "b | annotation just for debugging",
                    config.witness,
                    1,
                    || self.b,
                )?;
                // by default, cells all have value 0 (except maybe the very last few rows, where there are "blinding factors" for zero knowledge)

                // we need to compute the witness for a | b on our own somehow
                // let's emphasize this can be done in a different way than the gate:
                // an annoyance: a.value(), b.value() are both `Value<F>` meaning they can be either the value itself or None, so here comes ugly code:
                let out_val = a.value().zip(b.value()).map(|(a, b)| {
                    // now a,b are both type &F
                    let [a, b] = [a, b].map(|x| {
                        if x == &F::one() {
                            true
                        } else {
                            assert_eq!(x, &F::zero()); // this is just an assumption check, not a circuit constraint
                            false
                        }
                    });
                    // now a,b are bool
                    let out = a || b;
                    // we return the bool as an F value
                    F::from(out)
                });
                // out_val is now type `Value<F>`
                // we put this in row 2:
                // | row | witness | selector |
                // | 0   | a       |          |
                // | 1   | b       |          |
                // | 2   | a || b  |          |
                let _out =
                    region.assign_advice(|| "a OR b output", config.witness, 2, || out_val)?;

                // but wait, selector column defaults to all 0s, so no gates are actually turned "on"
                // we need to turn our OR gate on in row 0 only:
                // | row | witness | selector |
                // | 0   | a       | 1        |
                // | 1   | b       | 0        |
                // | 2   | a || b  | 0        |
                config.selector.enable(&mut region, 0)?;

                // Now the circuit will constrain `out_val` must equal `a + b - a * b` using the OR gate
                // For debugging you can also print out the literally cell containing `out_val`:
                println!("out cell: {_out:?}");
                // for just the value:
                // println!("out value: {:?}", _out.value());
                Ok(())
            },
        )
    }
}

// cfg(test) tells rust to only compile this in test mode
#[cfg(test)]
mod test {
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::bn256::Fr};

    use super::OrCircuit;

    // this marks the function as a test
    #[test]
    fn test_or() {
        let k = 5;
        // when actually running a circuit, we specialize F to the scalar field of BN254, denoted Fr
        let circuit = OrCircuit { a: Value::known(Fr::one()), b: Value::known(Fr::one()) };

        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }
}
