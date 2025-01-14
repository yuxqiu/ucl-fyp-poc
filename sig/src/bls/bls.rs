use std::ops::Mul;

use ark_bls12_381::{
    g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
    g2::{G2_GENERATOR_X, G2_GENERATOR_Y},
    Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    bls12,
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::{Pairing, PairingOutput},
};
use ark_ff::{field_hashers::DefaultFieldHasher, AdditiveGroup, UniformRand};
use ark_std::rand::Rng;
use blake2::Blake2s256;

type G1 = G1Projective;
type G2 = G2Projective;

#[derive(Clone)]
pub struct Parameters {
    pub g1_generator: G1,
    pub g2_generator: G2,
}

#[derive(Clone)]
pub struct PublicKey {
    pub pub_key: G1,
}

#[derive(Clone)]
pub struct SecretKey {
    pub secret_key: Fr,
}

#[derive(Clone)]
pub struct Signature {
    pub signature: G2,
}

impl Parameters {
    pub fn setup() -> Self {
        Parameters {
            g1_generator: G1Affine::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y).into(),
            g2_generator: G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y).into(),
        }
    }
}

impl PublicKey {
    pub fn new(secret_key: &SecretKey, params: &Parameters) -> Self {
        let pub_key = params.g1_generator.mul(secret_key.secret_key);
        Self { pub_key }
    }
}

impl SecretKey {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let secret_key = Fr::rand(rng);
        Self { secret_key }
    }
}

impl Signature {
    fn hash_to_curve(message: &[u8]) -> G2 {
        // safety
        type FieldHasher = DefaultFieldHasher<Blake2s256, 128>;
        type CurveMap = WBMap<ark_bls12_381::g2::Config>;
        let hasher: MapToCurveBasedHasher<G2Projective, FieldHasher, CurveMap> =
            MapToCurveBasedHasher::new(&[]).unwrap();
        let hashed_message: G2Affine = hasher.hash(message).unwrap();

        hashed_message.into()

        // For Testing Purpose
        // G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y).into()
    }

    pub fn sign(message: &[u8], secret_key: &SecretKey, _: &Parameters) -> Self {
        let hashed_message = Signature::hash_to_curve(message);
        let signature = hashed_message.mul(secret_key.secret_key);
        Self { signature }
    }

    pub fn aggregate_sign(
        message: &[u8],
        secret_keys: &[SecretKey],
        params: &Parameters,
    ) -> Option<Signature> {
        // we can theoretically do the following, but to mimic the real-world scenario,
        // let's sign them one by one and then add all sigs together

        /*
        if secret_keys.is_empty() {
            return None;
        }

        let sk = secret_keys
            .iter()
            .skip(1)
            .fold(secret_keys[0].clone(), |acc, new_sk| SecretKey {
                secret_key: acc.secret_key + new_sk.secret_key,
            });

        Some(Signature::sign(message, &sk, params))
        */

        let mut sigs = secret_keys
            .iter()
            .map(|sk| Signature::sign(message, sk, params));
        let first_sig = sigs.next()?;

        Some(sigs.fold(first_sig, |acc, new_sig| Signature {
            signature: acc.signature + new_sig.signature,
        }))
    }

    pub fn verify_slow(
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
        params: &Parameters,
    ) -> bool {
        let hashed_message = Signature::hash_to_curve(message);

        // a naive way to check pairing equation: e(g1, sig) == e(pk, H(msg))
        let pairing_1 = bls12::Bls12::<ark_bls12_381::Config>::pairing(
            params.g1_generator,
            signature.signature,
        );
        let pairing_2 = ark_ec::bls12::Bls12::<ark_bls12_381::Config>::pairing(
            public_key.pub_key,
            hashed_message,
        );

        pairing_1 == pairing_2
    }

    pub fn verify(
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
        params: &Parameters,
    ) -> bool {
        let hashed_message = Signature::hash_to_curve(message);

        // an optimized way to check pairing equation: e(g1, sig) == e(pk, H(msg))
        //
        // e'(g1, sig)^x == e'(pk, H(msg))^x (do miller loop for two sides without final exponentiation)
        // <=> check e'(g1, sig)^-x * e'(pk, H(msg))^x = 1
        // <=> check e'(-g1, sig)^x * e'(pk, H(msg))^x = 1
        let prod = ark_ec::bls12::Bls12::<ark_bls12_381::Config>::multi_pairing(
            [-params.g1_generator, public_key.pub_key],
            [signature.signature, hashed_message],
        );

        prod == PairingOutput::ZERO
    }

    pub fn aggregate_verify(
        message: &[u8],
        aggregate_signature: &Signature,
        public_keys: &[PublicKey],
        params: &Parameters,
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

        Some(Signature::verify_slow(
            message,
            aggregate_signature,
            &pk,
            params,
        ))
    }
}
