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
struct TestEccMul<C: CurveAffine> {
    window_size: usize,
    aux_generator: C,
}

impl<C: CurveAffine> Circuit<C::Scalar> for TestEccMul<C> {
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
                ecc_chip.assign_aux(ctx, self.window_size, 1)?;
                ecc_chip.get_mul_aux(self.window_size, 1)?;
                Ok(())
            },
        )?;

        layouter.assign_region(
            || "region 0",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let base = C::CurveExt::random(OsRng);
                let s = C::Scalar::random(OsRng);
                let result = base * s;

                let base = ecc_chip.assign_point(ctx, Value::known(base.into()))?;
                let s = main_gate.assign_value(ctx, Value::known(s))?;
                let result_0 = ecc_chip.assign_point(ctx, Value::known(result.into()))?;

                let result_1 = ecc_chip.mul(ctx, &base, &s, self.window_size)?;
                ecc_chip.assert_equal(ctx, &result_0, &result_1)?;

                Ok(())
            },
        )?;

        config.config_range(&mut layouter)?;

        Ok(())
    }
}

fn run<C: CurveAffine>()
where
    C::Scalar: FromUniformBytes<64>,
{
        for window_size in 1..5 {
            let aux_generator = <C as CurveAffine>::CurveExt::random(OsRng).to_affine();

            let circuit = TestEccMul {
                aux_generator,
                window_size,
            };
            let instance = vec![vec![]];
            mock_prover_verify(&circuit, instance);
        }
}

fn test_base_field_ecc_mul_circuit() {
    
    run::<Bn256>();
    //run::<Pallas>();
    //run::<Vesta>();
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let count = 10;
    let mut group = c.benchmark_group("mul bench");
    group.significance_level(0.1).sample_size(10);
    group.bench_function("mul", |b| b.iter(|| test_base_field_ecc_mul_circuit()));
    group.finish();


    //c.bench_function("mul bench", |b| b.iter(|| test_base_field_ecc_mul_circuit()));

}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);