use core::ops::Mul;

use ark_ec::{
    bls12::Bls12Config,
    hashing::{
        curve_maps::wb::{WBConfig, WBMap},
        map_to_curve_hasher::MapToCurveBasedHasher,
        HashToCurve,
    },
    pairing::{Pairing, PairingOutput},
    short_weierstrass::Projective,
    CurveConfig,
};
use ark_ff::{field_hashers::DefaultFieldHasher, AdditiveGroup, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::Blake2s256;
use derivative::Derivative;
use rand::Rng;

use super::HashCurveConfig;

#[derive(Derivative, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone(bound = ""))]
pub struct Parameters<P: Bls12Config> {
    pub g1_generator: Projective<P::G1Config>,
    pub g2_generator: Projective<P::G2Config>,
}

#[derive(Derivative, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone(bound = ""))]
pub struct PublicKey<P: Bls12Config> {
    pub pub_key: Projective<P::G1Config>,
}

#[derive(Derivative, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone(bound = ""))]
pub struct SecretKey<P: Bls12Config> {
    pub secret_key: <P::G1Config as CurveConfig>::ScalarField,
}

#[derive(Derivative, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone(bound = ""))]
pub struct Signature<P: Bls12Config> {
    pub signature: Projective<HashCurveConfig<P>>,
}

impl<P: Bls12Config> Parameters<P> {
    #[must_use]
    pub fn setup(
        g1_generator: Projective<P::G1Config>,
        g2_generator: Projective<P::G2Config>,
    ) -> Self {
        Self {
            g1_generator,
            g2_generator,
        }
    }
}

impl<P: Bls12Config> PublicKey<P> {
    #[must_use]
    pub fn new(secret_key: &SecretKey<P>, params: &Parameters<P>) -> Self {
        let pub_key = params.g1_generator.mul(secret_key.secret_key);
        Self { pub_key }
    }
}

impl<P: Bls12Config> SecretKey<P> {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let secret_key = <P::G1Config as CurveConfig>::ScalarField::rand(rng);
        Self { secret_key }
    }
}

impl<P: Bls12Config> Signature<P>
where
    HashCurveConfig<P>: WBConfig,
{
    fn hash_to_curve(message: &[u8]) -> Projective<HashCurveConfig<P>> {
        type FieldHasher = DefaultFieldHasher<Blake2s256, 128>;
        type CurveMap<P> = WBMap<HashCurveConfig<P>>;
        let hasher: MapToCurveBasedHasher<Projective<HashCurveConfig<P>>, FieldHasher, CurveMap<P>> =
            MapToCurveBasedHasher::new(&[]).unwrap();
        let hashed_message = hasher.hash(message).unwrap();
        hashed_message.into()
    }

    #[must_use]
    pub fn sign(message: &[u8], secret_key: &SecretKey<P>, _: &Parameters<P>) -> Self {
        let hashed_message = Self::hash_to_curve(message);
        let signature = hashed_message.mul(secret_key.secret_key);
        Self { signature }
    }

    #[must_use]
    pub fn aggregate_sign(
        message: &[u8],
        secret_keys: &[SecretKey<P>],
        params: &Parameters<P>,
    ) -> Option<Self> {
        let mut sigs = secret_keys.iter().map(|sk| Self::sign(message, sk, params));
        let first_sig = sigs.next()?;
        Some(sigs.fold(first_sig, |acc, new_sig| Self {
            signature: acc.signature + new_sig.signature,
        }))
    }

    #[must_use]
    pub fn verify_slow(
        message: &[u8],
        signature: &Self,
        public_key: &PublicKey<P>,
        params: &Parameters<P>,
    ) -> bool {
        let hashed_message = Self::hash_to_curve(message);
        let pairing_1 =
            ark_ec::bls12::Bls12::<P>::pairing(params.g1_generator, signature.signature);
        let pairing_2 = ark_ec::bls12::Bls12::<P>::pairing(public_key.pub_key, hashed_message);
        pairing_1 == pairing_2
    }

    #[must_use]
    pub fn verify(
        message: &[u8],
        signature: &Self,
        public_key: &PublicKey<P>,
        params: &Parameters<P>,
    ) -> bool {
        let hashed_message = Self::hash_to_curve(message);
        let prod = ark_ec::bls12::Bls12::<P>::multi_pairing(
            [-params.g1_generator, public_key.pub_key],
            [signature.signature, hashed_message],
        );
        prod == PairingOutput::ZERO
    }

    #[must_use]
    pub fn aggregate_verify(
        message: &[u8],
        aggregate_signature: &Self,
        public_keys: &[PublicKey<P>],
        params: &Parameters<P>,
    ) -> Option<bool> {
        if public_keys.is_empty() {
            return None;
        }
        let pk = public_keys
            .iter()
            .skip(1)
            .fold(public_keys[0].clone(), |acc, new_pk| PublicKey {
                pub_key: acc.pub_key + new_pk.pub_key,
            });
        Some(Self::verify_slow(message, aggregate_signature, &pk, params))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Config as Bls12_381Config;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use rand::thread_rng;

    // Type aliases for BLS12-381
    type TestParameters = Parameters<Bls12_381Config>;
    type TestPublicKey = PublicKey<Bls12_381Config>;
    type TestSecretKey = SecretKey<Bls12_381Config>;
    type TestSignature = Signature<Bls12_381Config>;

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
        const N: usize = 1000;

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
    fn test_setup() {
        let g1_gen = <Bls12_381Config as Bls12Config>::G1Config::GENERATOR.into();
        let g2_gen = <Bls12_381Config as Bls12Config>::G2Config::GENERATOR.into();
        let params = TestParameters::setup(g1_gen, g2_gen);
        // Basic check to ensure setup doesn't panic
        assert_eq!(params.g1_generator, g1_gen);
        assert_eq!(params.g2_generator, g2_gen);
    }

    #[test]
    fn check_signature() {
        let (msg, params, _, pk, sig) = get_instance();
        assert!(TestSignature::verify_slow(
            msg.as_bytes(),
            &sig,
            &pk,
            &params
        ));
        assert!(TestSignature::verify(msg.as_bytes(), &sig, &pk, &params));
    }

    #[test]
    fn check_verify_failure() {
        let (msg, params, _, pk, sig) = get_instance();
        assert!(!TestSignature::verify_slow(
            &[msg.as_bytes(), &[1]].concat(),
            &sig,
            &pk,
            &params
        ));
        assert!(!TestSignature::verify(
            &[msg.as_bytes(), &[1]].concat(),
            &sig,
            &pk,
            &params
        ));
    }

    #[test]
    fn check_aggregate_signature() {
        let (msg, params, _, public_keys, sig) = get_aggregate_instances();
        assert!(
            TestSignature::aggregate_verify(msg.as_bytes(), &sig, &public_keys, &params).unwrap()
        );
    }
}
