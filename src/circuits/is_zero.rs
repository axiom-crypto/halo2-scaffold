use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

#[derive(Clone, Copy, Debug)]
pub struct IsZeroConfig {
    x: Column<Advice>,
    y: Column<Advice>,
    out: Column<Advice>,
    selector: Selector,
}

// Our circuit is going to look like:
// x   | y   | out   | selector
// x_0 | y_0 | out_0 | s_0
// x_1 | y_1 | out_1 | s_1
// x_2 | y_2 | out_2 | s_2
// ...
// with constraints:
// MUL_ADD1: s_i * (x_i * y_i + out_i - 1) = 0
// MUL_0:    s_i * (x_i * out_i) = 0

impl IsZeroConfig {
    // it is standard practice to define everything where numbers are in a generic prime field `F` (`FieldExt` are the traits of a prime field)
    // `meta` is provided by the halo2 backend, it is the api for specifying PLONKish arithmetization grid shape + storing circuit constraints in polynomial form
    pub fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        let [x, y, out] = [(); 3].map(|_| meta.advice_column());
        let selector = meta.selector();

        // specify the columns that you may want to impose equality constraints on cells for (this may include fixed columns)
        // `y` is some internal column that we don't expose, so we probably don't need equality constraints on it
        [x, out].map(|column| meta.enable_equality(column));

        // we create a single is_zero gate with the two constraints MUL_ADD1 and MUL_0
        meta.create_gate("ISZERO gate", |meta| {
            // this gate will be applied AT EVERY ROW

            // we `query` for the `Expression` corresponding to the cell entry in a particular column at a relative row offset
            let [x, y, out] = [x, y, out].map(|column| meta.query_advice(column, Rotation::cur()));
            let s = meta.query_selector(selector);

            let xy = x.clone() * y;

            // specify all polynomial expressions that we require to equal zero
            // `Expression` is basically an abstract container for the polynomial corresponding to a column; in particular it can't implement `Copy` so we need to clone it to pass rust ownership rules
            vec![s.clone() * (xy + out.clone() - Expression::Constant(F::one())), s * x * out]
        });

        Self { x, y, out, selector }
    }
}

// we use the config to make a circuit:
// a circuit struct just holds the public/private inputs of a particular input for the circuit to compute
// slightly counterintuitive since the ZKCircuit is only created once, but it is then run multiple times with different inputs
// you should think that during actual ZKCircuit creation, these are just placeholders for the actual inputs
#[derive(Clone, Default)]
pub struct IsZeroCircuit<F: FieldExt> {
    // let's say our circuit wants to compute x == 0 ? 1 : 0
    pub x: Value<F>, // Value is a wrapper for rust `Option` with some arithmetic operator overloading
}

// now we implement the halo2 `Circuit` trait for our struct to actually make it a circuit
impl<F: FieldExt> Circuit<F> for IsZeroCircuit<F> {
    type Config = IsZeroConfig; // our earlier config
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
        IsZeroConfig::configure::<F>(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "IsZero circuit, only using 1 region",
            |mut region| {
                // for performance, it is better to avoid the ? operator; see https://github.com/rust-lang/rust/issues/37939

                // self.x, is the private inputs
                // we need to first load it into our circuit
                // | row | x      | y | out | selector |
                // | 0   | self.x |   |     |          |

                // The API calls witness cells "advice"
                // For mysterious reasons (weird rust trait issues), this function takes closures
                let x = region.assign_advice(
                    || "a | annotation just for debugging",
                    config.x,
                    0,
                    || self.x,
                )?;
                // by default, cells all have value 0 (except maybe the very last few rows, where there are "blinding factors" for zero knowledge)

                // We need to compute the witness for y = x == 0 ? 1 : x^{-1}
                // x.value() is of type `Value<F>` which means it can be either the underlying value or None, which leads to ugly code:
                let y_val =
                    x.value().map(|x| if x == &F::zero() { F::one() } else { x.invert().unwrap() });
                // we assign this to the y column in row 0
                // | row | x      | y     | out | selector |
                // | 0   | self.x | y_val |     |          |
                let _y = region.assign_advice(|| "y", config.y, 0, || y_val)?;

                // Entirely separately we can just compute the witness for out = x == 0 ? 1 : 0 the normal way
                let out_val = x.value().map(|x| if x == &F::zero() { F::one() } else { F::zero() });
                // | row | x      | y     | out     | selector |
                // | 0   | self.x | y_val | out_val |          |
                let out = region.assign_advice(|| "is_zero out", config.out, 0, || out_val)?;
                dbg!(&out);

                // but wait, selector column defaults to all 0s, so no gates are actually turned "on"
                // we need to turn our ISZERO gate on in row 0 only:
                // | row | x      | y     | out     | selector |
                // | 0   | self.x | y_val | out_val | 1        |
                config.selector.enable(&mut region, 0)?;

                // Let's say we want to use `out` somewhere else, here's how to do that:
                // | row | x      | y     | out     | selector |
                // | 0   | self.x | y_val | out_val | 1        |
                // | 1   | out    |       |         |          |
                out.copy_advice(|| "copy out", &mut region, config.x, 1)?;
                // this is exactly the same as the following two lines of code:
                // let out_copy = region.assign_advice(|| "copy out", config.x, 1, || out_val)?;
                // region.constrain_equal(out.cell(), out_copy.cell())?;
                Ok(())
            },
        )
    }
}

// cfg(test) tells rust to only compile this in test mode
#[cfg(test)]
mod test {
    use halo2_proofs::{
        arithmetic::Field, circuit::Value, dev::MockProver, halo2curves::bn256::Fr,
    };
    use rand::rngs::OsRng;

    use super::IsZeroCircuit;

    // this marks the function as a test
    #[test]
    fn test_is_zero_zero() {
        let k = 5;
        // when actually running a circuit, we specialize F to the scalar field of BN254, denoted Fr
        let circuit = IsZeroCircuit { x: Value::known(Fr::from(0)) };

        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }

    #[test]
    fn test_is_zero_random() {
        let k = 5;
        // when actually running a circuit, we specialize F to the scalar field of BN254, denoted Fr
        let circuit = IsZeroCircuit { x: Value::known(Fr::random(OsRng)) };

        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }
}
