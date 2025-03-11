use core::borrow::Borrow;

use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
use ark_ec::bls12::{Bls12, Bls12Config};
use ark_ec::hashing::curve_maps::swu::SWUConfig;
use ark_ec::hashing::curve_maps::wb::WBConfig;
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::Projective;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{Field, Fp2ConfigWrapper, PrimeField, QuadExtConfig};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::{FieldOpsBounds, FieldVar};
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::pairing::bls12;
use ark_r1cs_std::prelude::{Boolean, PairingVar};
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{Namespace, SynthesisError};

// Generic BLS12 curve config `P` and SNARK curve `S`
use ark_r1cs_std::groups::bls12::{G1PreparedVar, G1Var, G2PreparedVar, G2Var};
use derivative::Derivative;

use crate::bls::HashCurveVar;
// use crate::fp_var;
use crate::hash::hash_to_curve::cofactor::CofactorGadget;
use crate::hash::hash_to_curve::MapToCurveBasedHasherGadget;
use crate::hash::hash_to_field::default_hasher::DefaultFieldHasherGadget;
use crate::hash::hash_to_field::from_base_field::FromBaseFieldGadget;
use crate::hash::map_to_curve::sqrt::SqrtGadget;
use crate::hash::map_to_curve::to_base_field::ToBaseFieldGadget;
use crate::hash::map_to_curve::wb::WBMapGadget;

// Assuming `Parameters`, `PublicKey`, and `Signature` are generic from the previous file
use super::{HashCurveConfig, Parameters, PublicKey, Signature};

// Generic type definitions
type G1Gadget<P, FV, Fp> = G1Var<P, FV, Fp>;
type G2Gadget<P, FV, Fp> = G2Var<P, FV, Fp>;

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ParametersVar<P: Bls12Config, FV: FieldVar<<P as Bls12Config>::Fp, Fp>, Fp: PrimeField>
where
    for<'a> &'a FV: FieldOpsBounds<'a, <P as Bls12Config>::Fp, FV>,
{
    pub g1_generator: G1Gadget<P, FV, Fp>,
    pub g2_generator: G2Gadget<P, FV, Fp>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct PublicKeyVar<P: Bls12Config, FV: FieldVar<<P as Bls12Config>::Fp, Fp>, Fp: PrimeField>
where
    for<'a> &'a FV: FieldOpsBounds<'a, <P as Bls12Config>::Fp, FV>,
{
    pub pub_key: G1Gadget<P, FV, Fp>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct SignatureVar<P: Bls12Config, FV: FieldVar<<P as Bls12Config>::Fp, Fp>, Fp: PrimeField>
where
    for<'a> &'a FV: FieldOpsBounds<'a, <P as Bls12Config>::Fp, FV>,
{
    pub signature: G2Gadget<P, FV, Fp>,
}

pub struct BLSAggregateSignatureVerifyGadget<P, S, FV, Fp>
where
    P: Bls12Config,
    S: Pairing,
    FV: FieldVar<<P as Bls12Config>::Fp, Fp>
        + FromBaseFieldGadget<Fp>
        + ToBaseFieldGadget<<P as Bls12Config>::Fp, Fp>
        + SqrtGadget<<P as Bls12Config>::Fp, Fp>,
    Fp: PrimeField,
{
    // Phantom fields to hold the generic types without storing data
    _phantom_p: std::marker::PhantomData<P>,
    _phantom_fv: std::marker::PhantomData<FV>,
    _phantom_s: std::marker::PhantomData<S>,
    _phantom_fp: std::marker::PhantomData<Fp>,
}

impl<P, FV, S, Fp> BLSAggregateSignatureVerifyGadget<P, S, FV, Fp>
where
    P: Bls12Config,
    S: Pairing,
    FV: FieldVar<<P as Bls12Config>::Fp, Fp>
        + FromBaseFieldGadget<Fp>
        + ToBaseFieldGadget<<P as Bls12Config>::Fp, Fp>
        + SqrtGadget<<P as Bls12Config>::Fp, Fp>,
    Fp: PrimeField,
    for<'a> &'a FV: FieldOpsBounds<'a, <P as Bls12Config>::Fp, FV>,
{
    pub fn new() -> Self {
        Self {
            _phantom_p: std::marker::PhantomData,
            _phantom_fv: std::marker::PhantomData,
            _phantom_s: std::marker::PhantomData,
            _phantom_fp: std::marker::PhantomData,
        }
    }

    #[tracing::instrument(skip_all)]
    pub fn verify(
        &self,
        parameters: &ParametersVar<P, FV, Fp>,
        pk: &PublicKeyVar<P, FV, Fp>,
        message: &[UInt8<Fp>],
        signature: &SignatureVar<P, FV, Fp>,
    ) -> Result<(), SynthesisError>
    where
        HashCurveConfig<P>: WBConfig,
    {
        let cs = parameters.g1_generator.cs();

        tracing::info!(num_constraints = cs.num_constraints());

        let hash_to_curve = Self::hash_to_curve(message)?;

        let prod = bls12::PairingVar::product_of_pairings(
            &[
                G1PreparedVar::<P, FV, Fp>::from_group_var(&parameters.g1_generator.negate()?)?,
                G1PreparedVar::<P, FV, Fp>::from_group_var(&pk.pub_key)?,
            ],
            &[
                G2PreparedVar::from_group_var(&signature.signature)?,
                G2PreparedVar::from_group_var(&hash_to_curve)?,
            ],
        )?;

        prod.is_eq(&<bls12::PairingVar<P, FV, Fp> as PairingVar<
            Bls12<P>,
            Fp,
        >>::GTVar::new_constant(
            cs.clone(),
            <<Bls12<P> as Pairing>::TargetField as Field>::ONE,
        )?)?
        .enforce_equal(&Boolean::TRUE)?;

        tracing::info!(num_constraints = cs.num_constraints());

        Ok(())
    }

    pub fn verify_slow(
        &self,
        parameters: &ParametersVar<P, FV, Fp>,
        pk: &PublicKeyVar<P, FV, Fp>,
        message: &[UInt8<Fp>],
        signature: &SignatureVar<P, FV, Fp>,
    ) -> Result<(), SynthesisError>
    where
        HashCurveConfig<P>: WBConfig,
    {
        let hash_to_curve = Self::hash_to_curve(message)?;

        let signature_paired = bls12::PairingVar::pairing(
            G1PreparedVar::<P, FV, Fp>::from_group_var(&parameters.g1_generator)?,
            G2PreparedVar::from_group_var(&signature.signature)?,
        )?;
        let aggregated_pk_paired = bls12::PairingVar::pairing(
            G1PreparedVar::<P, FV, Fp>::from_group_var(&pk.pub_key)?,
            G2PreparedVar::from_group_var(&hash_to_curve)?,
        )?;

        signature_paired
            .is_eq(&aggregated_pk_paired)?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }

    pub fn aggregate_verify(
        &self,
        parameters: &ParametersVar<P, FV, Fp>,
        public_keys: &[PublicKeyVar<P, FV, Fp>],
        message: &[UInt8<Fp>],
        signature: &SignatureVar<P, FV, Fp>,
    ) -> Result<(), SynthesisError>
    where
        HashCurveConfig<P>: WBConfig,
    {
        let aggregated_pk =
            public_keys
                .iter()
                .skip(1)
                .fold(public_keys[0].clone(), |acc, new_pk| PublicKeyVar {
                    pub_key: acc.pub_key.clone() + &new_pk.pub_key,
                });

        self.verify(parameters, &aggregated_pk, message, signature)
    }

    #[tracing::instrument(skip_all)]
    fn hash_to_curve(msg: &[UInt8<Fp>]) -> Result<G2Gadget<P, FV, Fp>, SynthesisError>
    where
        HashCurveConfig<P>: WBConfig,
        Projective<HashCurveConfig<P>>: CofactorGadget<HashCurveVar<P, FV, Fp>, Fp>,
        <Projective<HashCurveConfig<P>> as CurveGroup>::Config: SWUConfig,
        HashCurveVar<P, FV, Fp>:
            FieldVar<<Projective<<P as Bls12Config>::G2Config> as CurveGroup>::BaseField, Fp>,
        for<'a> &'a HashCurveVar<P, FV, Fp>: FieldOpsBounds<
            'a,
            <Projective<<P as Bls12Config>::G2Config> as CurveGroup>::BaseField,
            HashCurveVar<P, FV, Fp>,
        >,
    {
        type HashGroupBaseField<P> = <HashCurveConfig<P> as CurveConfig>::BaseField;

        type FieldHasherGadget<P, FV, Fp> = DefaultFieldHasherGadget<
            Blake2sGadget<Fp>,
            HashGroupBaseField<P>,
            Fp,
            HashCurveVar<P, FV, Fp>,
            128,
        >;
        type CurveMapGadget<P> = WBMapGadget<HashCurveConfig<P>>;
        type HasherGadget<P, FV, Fp> = MapToCurveBasedHasherGadget<
            Projective<HashCurveConfig<P>>,
            FieldHasherGadget<P, FV, Fp>,
            CurveMapGadget<P>,
            Fp,
            HashCurveVar<P, FV, Fp>,
        >;

        let cs = msg.cs();
        tracing::info!(num_constraints = cs.num_constraints());

        let hasher_gadget = HasherGadget::<P, FV, Fp>::new(&[]);
        let hash = hasher_gadget.hash(msg)?;

        tracing::info!(num_constraints = cs.num_constraints());

        Ok(hash)
    }
}

// AllocVar implementations remain unchanged but need to reference the generic types
impl<P: Bls12Config, FV: FieldVar<<P as Bls12Config>::Fp, Fp>, Fp: PrimeField>
    AllocVar<Signature<P>, Fp> for SignatureVar<P, FV, Fp>
where
    G2Gadget<P, FV, Fp>: CurveVar<Projective<P::G2Config>, Fp>,
    for<'a> &'a FV: FieldOpsBounds<'a, <P as Bls12Config>::Fp, FV>,
{
    fn new_variable<T: Borrow<Signature<P>>>(
        cs: impl Into<Namespace<Fp>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            signature: G2Gadget::<P, FV, Fp>::new_variable(
                cs,
                || f().map(|value| value.borrow().signature),
                mode,
            )?,
        })
    }
}

impl<P: Bls12Config, FV: FieldVar<<P as Bls12Config>::Fp, Fp>, Fp: PrimeField>
    AllocVar<PublicKey<P>, Fp> for PublicKeyVar<P, FV, Fp>
where
    G1Gadget<P, FV, Fp>: CurveVar<Projective<P::G1Config>, Fp>,
    for<'a> &'a FV: FieldOpsBounds<'a, <P as Bls12Config>::Fp, FV>,
{
    fn new_variable<T: Borrow<PublicKey<P>>>(
        cs: impl Into<Namespace<Fp>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            pub_key: G1Gadget::<P, FV, Fp>::new_variable(
                cs,
                || f().map(|value| value.borrow().pub_key),
                mode,
            )?,
        })
    }
}

impl<P: Bls12Config, FV: FieldVar<<P as Bls12Config>::Fp, Fp>, Fp: PrimeField>
    AllocVar<Parameters<P>, Fp> for ParametersVar<P, FV, Fp>
where
    G1Gadget<P, FV, Fp>: CurveVar<Projective<P::G1Config>, Fp>,
    G2Gadget<P, FV, Fp>: CurveVar<Projective<P::G2Config>, Fp>,
    for<'a> &'a FV: FieldOpsBounds<'a, <P as Bls12Config>::Fp, FV>,
{
    fn new_variable<T: Borrow<Parameters<P>>>(
        cs: impl Into<Namespace<Fp>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let value = f();

        Ok(Self {
            g1_generator: G1Gadget::<P, FV, Fp>::new_variable(
                cs.clone(),
                || {
                    value
                        .as_ref()
                        .map(|value| value.borrow().g1_generator)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?,
            g2_generator: G2Gadget::<P, FV, Fp>::new_variable(
                cs,
                || {
                    value
                        .as_ref()
                        .map(|value| value.borrow().g2_generator)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::bls::SecretKey;

    use super::*;
    use ark_bls12_381::{Config as Bls12_381Config, G1Affine, G2Affine};
    use ark_bw6_761::BW6_761;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ff::BitIteratorBE;
    use ark_r1cs_std::{
        alloc::AllocVar,
        groups::{
            bls12::{G1PreparedVar, G2PreparedVar},
            CurveVar,
        },
        pairing::bls12,
        prelude::{Boolean, PairingVar},
        uint8::UInt8,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use rand::thread_rng;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    // Type aliases for BLS12-381 and BW6-761
    type Fp = <BW6_761 as Pairing>::ScalarField;
    type FV =
        ark_r1cs_std::fields::emulated_fp::EmulatedFpVar<<Bls12_381Config as Bls12Config>::Fp, Fp>;
    type TestParameters = Parameters<Bls12_381Config>;
    type TestPublicKey = PublicKey<Bls12_381Config>;
    type TestSecretKey = SecretKey<Bls12_381Config>;
    type TestSignature = Signature<Bls12_381Config>;
    type TestParametersVar = ParametersVar<Bls12_381Config, FV, Fp>;
    type TestPublicKeyVar = PublicKeyVar<Bls12_381Config, FV, Fp>;
    type TestSignatureVar = SignatureVar<Bls12_381Config, FV, Fp>;

    fn get_instance() -> (
        &'static str,
        TestParameters,
        TestSecretKey,
        TestPublicKey,
        TestSignature,
    ) {
        let msg = "Hello World";
        let mut rng = thread_rng();

        let g1_gen = <Bls12_381Config as Bls12Config>::G1Config::GENERATOR.into();
        let g2_gen = <Bls12_381Config as Bls12Config>::G2Config::GENERATOR.into();
        let params = TestParameters::setup(g1_gen, g2_gen);
        let sk = TestSecretKey::new(&mut rng);
        let pk = TestPublicKey::new(&sk, &params);

        let sig = TestSignature::sign(msg.as_bytes(), &sk, &params);

        (msg, params, sk, pk, sig)
    }

    fn get_aggregate_instances() -> (
        &'static str,
        TestParameters,
        Vec<TestSecretKey>,
        Vec<TestPublicKey>,
        TestSignature,
    ) {
        const N: usize = 10; // Reduced for test speed

        let msg = "Hello World";
        let mut rng = thread_rng();

        let g1_gen = <Bls12_381Config as Bls12Config>::G1Config::GENERATOR.into();
        let g2_gen = <Bls12_381Config as Bls12Config>::G2Config::GENERATOR.into();
        let params = TestParameters::setup(g1_gen, g2_gen);
        let secret_keys: Vec<TestSecretKey> =
            (0..N).map(|_| TestSecretKey::new(&mut rng)).collect();
        let public_keys: Vec<TestPublicKey> = secret_keys
            .iter()
            .map(|sk| TestPublicKey::new(sk, &params))
            .collect();

        let sig = TestSignature::aggregate_sign(msg.as_bytes(), &secret_keys, &params).unwrap();

        (msg, params, secret_keys, public_keys, sig)
    }

    #[test]
    fn check_r1cs() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let (msg, params, _, pk, sig) = get_instance();

        let msg_var: Vec<UInt8<Fp>> = msg
            .as_bytes()
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let params_var = TestParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();
        let pk_var = TestPublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap();
        let sig_var = TestSignatureVar::new_input(cs.clone(), || Ok(sig)).unwrap();

        let gadget = BLSAggregateSignatureVerifyGadget::<Bls12_381Config, BW6_761, FV, Fp>::new();
        gadget
            .verify(&params_var, &pk_var, &msg_var, &sig_var)
            .unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
        println!("R1CS is satisfied!");
    }

    #[test]
    fn emulation_bug_example() {
        let cs = ConstraintSystem::<Fp>::new_ref();
        let (_, params, _, pk, sig) = get_instance();

        let params_var = TestParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();
        let pk_var = TestPublicKeyVar::new_constant(cs.clone(), pk).unwrap();
        let sig_var = TestSignatureVar::new_constant(cs.clone(), sig).unwrap();

        // Debug Story: Aggregate Sig -> product_of_pairing -> miller loop ->
        /*
             // for convenience, just read 0
            if let Some(p) = ps.get(0) {
                let cs = p.0.x.cs();
                tracing::info!(num_constraints = cs.num_constraints());
            }

            let mut pairs = vec![];
            for (p, q) in ps.iter().zip(qs.iter()) {
                pairs.push((p, q.ell_coeffs.iter()));
            }
            let mut f = Self::GTVar::one();

            for i in BitIteratorBE::new(P::X).skip(1) {
                f.square_in_place()?;

                for &mut (p, ref mut coeffs) in pairs.iter_mut() {
                    Self::ell(&mut f, coeffs.next().unwrap(), &p.0)?;
                }

                if i {
                    for &mut (p, ref mut coeffs) in pairs.iter_mut() {
                        Self::ell(&mut f, &coeffs.next().unwrap(), &p.0)?;
                    }
                }
            }
        */
        // -> ell -> partial ell

        let ps = [
            G1PreparedVar::<Bls12_381Config, FV, Fp>::from_group_var(
                &params_var.g1_generator.negate().unwrap(),
            )
            .unwrap(),
            G1PreparedVar::<Bls12_381Config, FV, Fp>::from_group_var(&pk_var.pub_key).unwrap(),
        ];
        let qs: [G2PreparedVar<Bls12_381Config, FV, Fp>; 2] = [
            G2PreparedVar::from_group_var(&sig_var.signature).unwrap(),
            G2PreparedVar::from_group_var(&params_var.g2_generator).unwrap(),
        ];

        let mut pairs = vec![];
        for (p, q) in ps.iter().zip(qs.iter()) {
            pairs.push((p, q.ell_coeffs.iter()));
        }

        type MyPairingVar = bls12::PairingVar<Bls12_381Config, FV, Fp>;
        let mut f = <MyPairingVar as PairingVar<Bls12<Bls12_381Config>, Fp>>::GTVar::one();

        for (idx, i) in BitIteratorBE::new(<Bls12_381Config as Bls12Config>::X)
            .skip(1)
            .enumerate()
        {
            println!("at {}", idx);

            f.square_in_place().unwrap();
            println!(
                "cs.satisfied = {} at {}",
                cs.is_satisfied().unwrap(),
                line!()
            );

            for &mut (p, ref mut coeffs) in pairs.iter_mut() {
                MyPairingVar::ell(&mut f, coeffs.next().unwrap(), &p.0).unwrap();
            }
            println!(
                "cs.satisfied = {} at {}",
                cs.is_satisfied().unwrap(),
                line!()
            );

            if i {
                for &mut (p, ref mut coeffs) in pairs.iter_mut() {
                    MyPairingVar::ell(&mut f, coeffs.next().unwrap(), &p.0).unwrap();
                }
            }
            println!(
                "cs.satisfied = {} at {}",
                cs.is_satisfied().unwrap(),
                line!()
            );

            assert!(cs.is_satisfied().unwrap());
            println!();
        }

        // let s: CubicExtField<Fp6ConfigWrapper<<BLSSigCurveConfig as Bls12Config>::Fp6Config>> = CubicExtField { c0: QuadExtField { c0: BaseSigCurveField::new(BigInt!("1396647618126876491551238897028281182182662946814742239452658799494849612884112015940766337389283670758378407669858")), c1: BaseSigCurveField::new(BigInt!("489300199753474263487139255028045766852234638962321376174587026474133093607716596781998693009932963140607730310874")) }, c1: QuadExtField { c0: BaseSigCurveField::new(BigInt!("2076779849093790960004645082128074049749284347384508349411906451297833786449525588244671694689239114308470534722")), c1: BaseSigCurveField::new(BigInt!("3429111531654932568292424302827161866150960261911970054523238888922579513273636064340952974092751506611613309106989")) }, c2: QuadExtField { c0: BaseSigCurveField::new(BigInt!("3105552301778060130939400582219924301640386073897117038804000010537014450986416157402674422832457578419365373540100")), c1: BaseSigCurveField::new(BigInt!("3876225650084791655496417842379490798548983675921971746960092311091188678494876118677610567726216270877190335329985")) } };
        // let c0 = QuadExtField { c0: BaseSigCurveField::new(BigInt!("3793885288740742725797458173051012191755498788871183885026428963711034866571316645935841285200271690995591479553459")), c1: BaseSigCurveField::new(BigInt!("2996901763584276916617790377778099338968936475300200779862307371169240467862390136884092754318251205909929343510514")) };
        // let c1: QuadExtField<Fp2ConfigWrapper<<BLSSigCurveConfig as Bls12Config>::Fp2Config>> = QuadExtField { c0: BaseSigCurveField::new(BigInt!("1390118126216571966813929905681038212433944121124097261166221724113580654669884433532201829614388003564787124846154")), c1: BaseSigCurveField::new(BigInt!("3841297017270657899921787036732710213975700732339081708515654031471901412628370576261289604985108475530657932751769")) };

        // let sv = Fp6Var::new_input(cs.clone(), || Ok(s)).unwrap();
        // let c0v = Fp2Var::new_input(cs.clone(), || Ok(c0)).unwrap();
        // let c1v: QuadExtVar<
        //     fp_var!(BaseSigCurveField, BaseSNARKField),
        //     Fp2ConfigWrapper<ark_bls12_381::Fq2Config>,
        //     BaseSNARKField,
        // > = Fp2Var::new_input(cs.clone(), || Ok(c1)).unwrap();
        // let _ = sv.mul_by_c0_c1_0(&c0v, &c1v).unwrap();
        //
        // -> Fp6_3over2::mul_by_c0_c1_0 -> Fp6_3over2 (`let c1 = a0_plus_a1 * b0_plus_b1;`)

        println!("{}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn tracing_num_constraints() {
        let file_appender = tracing_appender::rolling::hourly("./", "constraints.log");
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(
                        tracing_subscriber::fmt::format::FmtSpan::EXIT
                            | tracing_subscriber::fmt::format::FmtSpan::ENTER,
                    )
                    .with_ansi(false)
                    .with_writer(non_blocking)
                    .with_filter(tracing_subscriber::filter::FilterFn::new(|metadata| {
                        metadata.target().contains("sig")
                            || ["miller_loop", "final_exponentiation"]
                                .into_iter()
                                .any(|s| metadata.name().contains(s))
                            || metadata.is_event()
                    })),
            )
            .init();

        let cs = ConstraintSystem::<Fp>::new_ref();
        let (msg, params, _, pk, sig) = get_instance();

        let msg_var: Vec<UInt8<Fp>> = msg
            .as_bytes()
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let params_var = TestParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();
        let pk_var = TestPublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap();
        let sig_var = TestSignatureVar::new_input(cs.clone(), || Ok(sig)).unwrap();

        let gadget = BLSAggregateSignatureVerifyGadget::<Bls12_381Config, BW6_761, FV, Fp>::new();
        gadget
            .verify(&params_var, &pk_var, &msg_var, &sig_var)
            .unwrap();

        let num_constraints = cs.num_constraints();
        tracing::info!("Number of constraints: {}", num_constraints);
        assert!(cs.is_satisfied().unwrap());
        tracing::info!("R1CS is satisfied!");
    }
}
