use std::marker::PhantomData;
use std::rc::Rc;

use integer::halo2;
use halo2::arithmetic::CurveAffine;
use integer::rns::Rns;
use integer::NUMBER_OF_LOOKUP_LIMBS;

use ecc::maingate::{
    AssignedValue, MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig,
    RangeInstructions,
};

use ecc::{AssignedPoint, EccConfig, Point};

use halo2::plonk::{Circuit, ConstraintSystem, Error};


use halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2::halo2curves::{
    ff::{Field, FromUniformBytes, PrimeField},
    group::{Curve as _, Group},
};


use integer::maingate::RegionCtx;
use ecc::BaseFieldEccChip;
use rand_core::OsRng;

use std::time::{Duration, Instant};
use ecc::maingate::mock_prover_verify;

use halo2::halo2curves::bn256::G1Affine as Bn256;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use paste::paste;

const NUMBER_OF_LIMBS: usize = 4;
const BIT_LEN_LIMB: usize = 68;

#[derive(Clone, Debug)]
struct TestCircuitConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl TestCircuitConfig {
    fn ecc_chip_config(&self) -> EccConfig {
        EccConfig {
            range_config: self.range_config.clone(),
            main_gate_config: self.main_gate_config.clone(),
        }
    }
}

impl TestCircuitConfig {
    fn new<C: CurveAffine>(meta: &mut ConstraintSystem<C::Scalar>) -> Self {
        let rns = Rns::<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct();

        let main_gate_config = MainGate::<C::Scalar>::configure(meta);
        let overflow_bit_lens = rns.overflow_lengths();
        let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

        let range_config = RangeChip::<C::Scalar>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        TestCircuitConfig {
            main_gate_config,
            range_config,
        }
    }
    fn config_range<N: PrimeField>(
        &self,
        layouter: &mut impl Layouter<N>,
    ) -> Result<(), Error> {
        let range_chip = RangeChip::<N>::new(self.range_config.clone());
        range_chip.load_table(layouter)?;

        Ok(())
    }
}

#[derive(Default, Clone, Debug)]
struct TestEccBatchMul<C: CurveAffine> {
    window_size: usize,
    number_of_pairs: usize,
    aux_generator: C,
}

impl<C: CurveAffine> Circuit<C::Scalar> for TestEccBatchMul<C> {
    type Config = TestCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
        TestCircuitConfig::new::<C>(meta)
    }

    #[allow(clippy::type_complexity)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::Scalar>,
    ) -> Result<(), Error> {
        let ecc_chip_config = config.ecc_chip_config();
        let mut ecc_chip =
            BaseFieldEccChip::<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);
        let main_gate = MainGate::<C::Scalar>::new(config.main_gate_config.clone());

        layouter.assign_region(
            || "assign aux values",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
                ecc_chip.assign_aux(ctx, self.window_size, self.number_of_pairs)?;
                ecc_chip.get_mul_aux(self.window_size, self.number_of_pairs)?;
                Ok(())
            },
        )?;

        layouter.assign_region(
            || "region 0",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let mut acc = C::CurveExt::identity();
                let pairs: Vec<(
                    AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
                    AssignedValue<C::Scalar>,
                )> = (0..self.number_of_pairs)
                    .map(|_| {
                        let base = C::CurveExt::random(OsRng);
                        let s = C::Scalar::random(OsRng);
                        acc += base * s;
                        let base = ecc_chip.assign_point(ctx, Value::known(base.into()))?;
                        let s = main_gate.assign_value(ctx, Value::known(s))?;
                        Ok((base, s))
                    })
                    .collect::<Result<_, Error>>()?;

                let result_0 = ecc_chip.assign_point(ctx, Value::known(acc.into()))?;
                let result_1 =
                    ecc_chip.mul_batch_1d_horizontal(ctx, pairs, self.window_size)?;
                ecc_chip.assert_equal(ctx, &result_0, &result_1)?;

                Ok(())
            },
        )?;

        config.config_range(&mut layouter)?;

        Ok(())
    }
}



fn test_base_field_ecc_mul_batch_circuit(){
    for number_of_pairs in 5..7 {
        for window_size in 1..3 {
            let aux_generator = <Bn256 as CurveAffine>::CurveExt::random(OsRng).to_affine();

            let circuit = TestEccBatchMul {
                aux_generator,
                window_size,
                number_of_pairs,
            };
            let instance = vec![vec![]];
            mock_prover_verify(&circuit, instance);
        }
    }
}


pub fn criterion_benchmark(c: &mut Criterion) {
    let count = 10;
    let mut group = c.benchmark_group("msm bench");
    group.significance_level(0.1).sample_size(10);
    group.bench_function("msm", |b| b.iter(|| test_base_field_ecc_mul_batch_circuit()));
    group.finish();


}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

//fn main(){}