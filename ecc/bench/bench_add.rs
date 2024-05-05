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

fn rns<C: CurveAffine>() -> Rns<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
    Rns::construct()
}

fn setup<C: CurveAffine>(
    k_override: u32,
) -> (Rns<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, u32) {
    let rns = rns::<C>();
    let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
    let mut k: u32 = (bit_len_lookup + 1) as u32;
    if k_override != 0 {
        k = k_override;
    }
    (rns, k)
}

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

#[derive(Clone, Debug, Default)]
struct TestEccAddition<C> {
    _marker: PhantomData<C>,
}

impl<C: CurveAffine> Circuit<C::Scalar> for TestEccAddition<C> {
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
        let ecc_chip =
            BaseFieldEccChip::<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);
        layouter.assign_region(
            || "region 0",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let a = C::CurveExt::random(OsRng);
                let b = C::CurveExt::random(OsRng);

                let c = a + b;
                let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                let b = &ecc_chip.assign_point(ctx, Value::known(b.into()))?;
                let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
                let c_1 = &ecc_chip.add(ctx, a, b)?;
                ecc_chip.assert_equal(ctx, c_0, c_1)?;

                //let c_1 = &ecc_chip.add(ctx, a, b)?;
                //ecc_chip.assert_equal(ctx, c_0, c_1)?;

                // test doubling

                /* 
                let a = C::CurveExt::random(OsRng);
                let c = a + a;

                let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
                let c_1 = &ecc_chip.double(ctx, a)?;
                ecc_chip.assert_equal(ctx, c_0, c_1)?;
                */


                // test ladder

                /* 

                let a = C::CurveExt::random(OsRng);
                let b = C::CurveExt::random(OsRng);
                let c = a + b + a;

                let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                let b = &ecc_chip.assign_point(ctx, Value::known(b.into()))?;
                let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
                let c_1 = &ecc_chip.ladder(ctx, a, b)?;
                ecc_chip.assert_equal(ctx, c_0, c_1)?;
                */
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

    // estimate the time of every part

    let circuit = TestEccAddition::<C>::default();
    
    let instance = vec![vec![]];

    mock_prover_verify(&circuit, instance);

}

fn test_base_field_ecc_addition_circuit() {
    // !!!----------------------------
    // modify the code
    // add the timer to see the performance

    //let start = Instant::now();

    run::<Bn256>();
    //run::<Pallas>();
    //run::<Vesta>();

    //let duration = start.elapsed();
    //println!("time: {:?}", duration);

    // !!!----------------------------
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("add bench", |b| b.iter(|| test_base_field_ecc_addition_circuit()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

// fn main(){
//     test_base_field_ecc_addition_circuit();


//     println!("hello world!");
// }