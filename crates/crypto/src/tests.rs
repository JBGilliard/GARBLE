use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    signatures::Signer,
    types::{AeadType, Ciphersuite, HashType, HpkeCiphertext, SignatureScheme},
};

use crate::{Crypto, NAME, SignatureKeyPair, crypto};

const SUITE_ID: Ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;

#[test]
fn suite_is_the_wire_constant() {
    assert_eq!(SUITE_ID as u16, proto::CIPHERSUITE);
}

#[test]
fn provider_matches_the_feature() {
    assert_eq!(NAME == "libcrux", cfg!(feature = "libcrux"));
}

// CI sets this per matrix leg; unset locally.
#[test]
fn ci_got_the_provider_it_asked_for() {
    if let Ok(want) = std::env::var("GARBLE_EXPECT_PROVIDER") {
        assert_eq!(NAME, want);
    }
}

#[test]
fn provider_runs_the_suite() {
    assert!(crypto().supports(SUITE_ID).is_ok());
}

#[test]
fn ml_dsa_87_sizes_and_round_trip() {
    let k = SignatureKeyPair::new(SignatureScheme::MLDSA87).unwrap();
    assert_eq!(k.public().len(), 2592);
    let sig = k.sign(b"msg").unwrap();
    assert_eq!(sig.len(), 4627);
    let c = crypto();
    let verify = |msg: &[u8], pk: &[u8], sig: &[u8]| {
        c.verify_signature(SignatureScheme::MLDSA87, msg, pk, sig)
    };
    assert!(verify(b"msg", k.public(), &sig).is_ok());
    assert!(verify(b"other", k.public(), &sig).is_err());
    let other = SignatureKeyPair::new(SignatureScheme::MLDSA87).unwrap();
    assert!(verify(b"msg", other.public(), &sig).is_err());
    let mut bent = sig.clone();
    bent[100] ^= 1;
    assert!(verify(b"msg", k.public(), &bent).is_err());
    assert!(verify(b"msg", k.public(), &sig[1..]).is_err());
    assert!(verify(b"msg", &k.public()[1..], &sig).is_err());
    assert!(verify(b"msg", k.public(), &[]).is_err());
}

#[test]
fn key_files_keep_the_basic_credential_shape() {
    let k = SignatureKeyPair::new(SignatureScheme::MLDSA87).unwrap();
    let json = serde_json::to_value(&k).unwrap();
    assert_eq!(json["signature_scheme"], "MLDSA87");
    assert_eq!(json["private"].as_array().unwrap().len(), 32);
    assert_eq!(json["public"].as_array().unwrap().len(), 2592);
    let back: SignatureKeyPair = serde_json::from_value(json).unwrap();
    assert_eq!(back.public(), k.public());
    let sig = back.sign(b"m").unwrap();
    assert!(
        crypto()
            .verify_signature(SignatureScheme::MLDSA87, b"m", k.public(), &sig)
            .is_ok()
    );
}

#[test]
fn debug_hides_the_private_key() {
    let k = SignatureKeyPair::new(SignatureScheme::MLDSA87).unwrap();
    assert!(format!("{k:?}").contains("***"));
}

#[test]
fn sha384_known_answer() {
    let got = crypto().hash(HashType::Sha2_384, b"abc").unwrap();
    assert_eq!(
        got,
        hex_to_bytes(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        )
    );
}

#[test]
fn aes_256_gcm_round_trip_and_tamper() {
    let c = crypto();
    let (key, nonce) = (c.random_vec(32).unwrap(), c.random_vec(12).unwrap());
    let ct = c
        .aead_encrypt(AeadType::Aes256Gcm, &key, b"plain", &nonce, b"aad")
        .unwrap();
    assert_eq!(ct.len(), 5 + 16);
    let open = |ct: &[u8], aad: &[u8]| c.aead_decrypt(AeadType::Aes256Gcm, &key, ct, &nonce, aad);
    assert_eq!(open(&ct, b"aad").unwrap(), b"plain");
    assert!(open(&ct, b"other").is_err());
    let mut bent = ct.clone();
    bent[0] ^= 1;
    assert!(open(&bent, b"aad").is_err());
}

#[test]
fn hpke_ml_kem_1024_round_trip() {
    let c = crypto();
    let ikm = c.random_vec(64).unwrap();
    let kp = c.derive_hpke_keypair(SUITE_ID.hpke_config(), &ikm).unwrap();
    assert_eq!(kp.public.len(), 1568);
    let sealed = c
        .hpke_seal(
            SUITE_ID.hpke_config(),
            &kp.public,
            b"info",
            b"aad",
            b"plain",
        )
        .unwrap();
    assert_eq!(sealed.kem_output.as_slice().len(), 1568); // ML-KEM-1024 ciphertext
    let open = |info: &[u8], aad: &[u8], ct: &HpkeCiphertext| {
        c.hpke_open(SUITE_ID.hpke_config(), ct, &kp.private, info, aad)
    };
    assert_eq!(open(b"info", b"aad", &sealed).unwrap(), b"plain");
    assert!(open(b"nope", b"aad", &sealed).is_err());
    assert!(open(b"info", b"nope", &sealed).is_err());

    // Same key schedule hook MLS uses for external commits.
    let (enc, a) = c
        .hpke_setup_sender_and_export(SUITE_ID.hpke_config(), &kp.public, b"", b"ctx", 48)
        .unwrap();
    let b = c
        .hpke_setup_receiver_and_export(SUITE_ID.hpke_config(), &enc, &kp.private, b"", b"ctx", 48)
        .unwrap();
    assert_eq!(a.as_ref(), b.as_ref());
}

#[test]
fn hpke_keys_derive_from_ikm() {
    let c = crypto();
    let ikm = [7u8; 64];
    let (a, b) = (
        c.derive_hpke_keypair(SUITE_ID.hpke_config(), &ikm).unwrap(),
        c.derive_hpke_keypair(SUITE_ID.hpke_config(), &ikm).unwrap(),
    );
    assert_eq!(a.public, b.public);
}

#[test]
fn random_is_not_constant() {
    let c: Crypto = crypto();
    assert_ne!(
        c.random_array::<32>().unwrap(),
        c.random_array::<32>().unwrap()
    );
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Only the libcrux provider refuses things; the RustCrypto one is permissive by design.
#[cfg(feature = "libcrux")]
mod libcrux_provider {
    use openmls_traits::types::{
        HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType,
    };

    use super::*;

    #[test]
    fn advertises_exactly_the_suite_and_supports_what_it_advertises() {
        let c = crypto();
        assert_eq!(c.supported_ciphersuites(), vec![SUITE_ID]);
        for cs in c.supported_ciphersuites() {
            assert!(c.supports(cs).is_ok());
        }
        // The RustCrypto provider says yes to these; the point is that we say no.
        for other in [
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
        ] {
            assert!(c.supports(other).is_err(), "{other:?}");
        }
    }

    #[test]
    fn refuses_primitives_outside_the_suite() {
        let c = crypto();
        assert!(c.hash(HashType::Sha2_256, b"x").is_err());
        assert!(c.hmac(HashType::Sha2_512, b"k", b"x").is_err());
        assert!(c.hkdf_extract(HashType::Sha2_256, b"s", b"i").is_err());
        assert!(
            c.hkdf_expand(HashType::Sha2_256, &[0; 32], b"i", 16)
                .is_err()
        );
        let (key, nonce) = ([0u8; 16], [0u8; 12]);
        assert!(
            c.aead_encrypt(AeadType::Aes128Gcm, &key, b"x", &nonce, b"")
                .is_err()
        );
        assert!(
            c.aead_encrypt(AeadType::ChaCha20Poly1305, &[0; 32], b"x", &nonce, b"")
                .is_err()
        );
        for alg in [
            SignatureScheme::ED25519,
            SignatureScheme::MLDSA44,
            SignatureScheme::MLDSA65,
        ] {
            assert!(c.signature_key_gen(alg).is_err(), "{alg:?}");
            assert!(c.sign(alg, b"m", &[0; 32]).is_err(), "{alg:?}");
            assert!(c.verify_signature(alg, b"m", &[0; 32], &[0; 64]).is_err());
        }
        let wrong = || {
            HpkeConfig(
                HpkeKemType::MlKem768,
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
            )
        };
        assert!(c.derive_hpke_keypair(wrong(), &[0; 64]).is_err());
        assert!(c.hpke_seal(wrong(), &[0; 1184], b"", b"", b"x").is_err());
        let ct = HpkeCiphertext {
            kem_output: vec![].into(),
            ciphertext: vec![].into(),
        };
        assert!(c.hpke_open(wrong(), &ct, &[0; 64], b"", b"").is_err());
    }

    // RUSTSEC-2026-0330/0331 (libcrux-kem 0.0.9): hybrid-KEM decoders panic on short
    // input. We never configure a hybrid KEM; these pin that the pure ML-KEM-1024 path
    // we do use errors instead, since `kem_output` arrives off the wire.
    #[test]
    fn malformed_kem_inputs_error_instead_of_panicking() {
        let c = crypto();
        let cfg = || SUITE_ID.hpke_config();
        let kp = c.derive_hpke_keypair(cfg(), &[5; 64]).unwrap();
        let sealed = c.hpke_seal(cfg(), &kp.public, b"i", b"a", b"x").unwrap();
        for len in [0usize, 1, 31, 32, 1183, 1184, 1567, 1569, 3167, 3169] {
            let junk = vec![0xAB; len];
            assert!(
                c.hpke_seal(cfg(), &junk, b"i", b"a", b"x").is_err(),
                "pk {len}"
            );
            let bad_ct = HpkeCiphertext {
                kem_output: junk.clone().into(),
                ciphertext: sealed.ciphertext.clone(),
            };
            assert!(
                c.hpke_open(cfg(), &bad_ct, &kp.private, b"i", b"a")
                    .is_err(),
                "ct {len}"
            );
            assert!(
                c.hpke_open(cfg(), &sealed, &junk, b"i", b"a").is_err(),
                "sk {len}"
            );
            assert!(
                c.hpke_setup_receiver_and_export(cfg(), &junk, &kp.private, b"", b"c", 48)
                    .is_err(),
                "enc {len}"
            );
            assert!(
                c.hpke_setup_sender_and_export(cfg(), &junk, b"", b"c", 48)
                    .is_err(),
                "export pk {len}"
            );
        }
    }

    // RUSTSEC-2026-0329 (libcrux-hmac-drbg 0.0.1): reseeding DRBG panicked on output
    // lengths that are a non-zero multiple of 65,536.
    #[test]
    fn random_survives_drbg_block_multiples() {
        let c = crypto();
        for len in [65_535usize, 65_536, 65_537, 131_072, 196_608] {
            assert_eq!(c.random_vec(len).unwrap().len(), len);
        }
    }

    #[test]
    fn sign_rejects_a_short_seed() {
        assert!(
            crypto()
                .sign(SignatureScheme::MLDSA87, b"m", &[0; 31])
                .is_err()
        );
    }

    #[test]
    fn same_seed_same_signature_key() {
        // Signatures are hedged, so two signatures differ; both must verify.
        let c = crypto();
        let (seed, pk) = c.signature_key_gen(SignatureScheme::MLDSA87).unwrap();
        let (s1, s2) = (
            c.sign(SignatureScheme::MLDSA87, b"m", &seed).unwrap(),
            c.sign(SignatureScheme::MLDSA87, b"m", &seed).unwrap(),
        );
        assert_ne!(s1, s2);
        for s in [s1, s2] {
            assert!(
                c.verify_signature(SignatureScheme::MLDSA87, b"m", &pk, &s)
                    .is_ok()
            );
        }
    }

    /// libcrux against RustCrypto's independent ML-DSA / ML-KEM / SHA / AES, so a bug in
    /// one of them (libcrux's ML-DSA had FIPS 204 bugs fixed in March 2026) shows up here.
    mod differential {
        use openmls_rust_crypto::RustCrypto;

        use super::*;

        fn rc() -> RustCrypto {
            RustCrypto::default()
        }

        const MLDSA: SignatureScheme = SignatureScheme::MLDSA87;

        #[test]
        fn ml_dsa_keys_and_signatures_cross_verify() {
            let (lx, rust) = (crypto(), rc());
            for i in 0..8u8 {
                let msg = vec![i; usize::from(i) * 37];

                // libcrux seed -> RustCrypto signs -> libcrux verifies under libcrux's pk.
                let (seed, pk) = lx.signature_key_gen(MLDSA).unwrap();
                let sig = rust.sign(MLDSA, &msg, &seed).unwrap();
                lx.verify_signature(MLDSA, &msg, &pk, &sig).unwrap();

                // And the other way round.
                let (seed, pk) = rust.signature_key_gen(MLDSA).unwrap();
                let sig = lx.sign(MLDSA, &msg, &seed).unwrap();
                rust.verify_signature(MLDSA, &msg, &pk, &sig).unwrap();
                // The same seed must expand to the same public key.
                let sig = rust.sign(MLDSA, &msg, &seed).unwrap();
                lx.verify_signature(MLDSA, &msg, &pk, &sig).unwrap();
            }
        }

        #[test]
        fn both_reject_every_single_bit_flip_we_try() {
            let (lx, rust) = (crypto(), rc());
            let (seed, pk) = lx.signature_key_gen(MLDSA).unwrap();
            let sig = lx.sign(MLDSA, b"signed", &seed).unwrap();
            for i in (0..sig.len()).step_by(97) {
                let mut bent = sig.clone();
                bent[i] ^= 0x10;
                assert_eq!(
                    lx.verify_signature(MLDSA, b"signed", &pk, &bent).is_ok(),
                    rust.verify_signature(MLDSA, b"signed", &pk, &bent).is_ok(),
                    "byte {i}"
                );
                assert!(lx.verify_signature(MLDSA, b"signed", &pk, &bent).is_err());
            }
            for i in (0..pk.len()).step_by(211) {
                let mut bent = pk.clone();
                bent[i] ^= 0x01;
                assert!(lx.verify_signature(MLDSA, b"signed", &bent, &sig).is_err());
                assert!(
                    rust.verify_signature(MLDSA, b"signed", &bent, &sig)
                        .is_err()
                );
            }
        }

        #[test]
        fn hpke_keys_and_ciphertexts_cross_open() {
            let (lx, rust) = (crypto(), rc());
            let cfg = || SUITE_ID.hpke_config();
            let ikm = [9u8; 64];
            let (a, b) = (
                lx.derive_hpke_keypair(cfg(), &ikm).unwrap(),
                rust.derive_hpke_keypair(cfg(), &ikm).unwrap(),
            );
            assert_eq!(a.public, b.public, "same ikm, different ML-KEM key");
            // Private halves are provider-specific: libcrux keeps the expanded
            // decapsulation key, RustCrypto the 64-byte seed. Public keys and
            // ciphertexts interoperate; a stored private key does not move providers.
            assert_eq!(a.private.as_ref().len(), 3168);
            assert_eq!(b.private.as_ref().len(), 64);

            let sealed = lx
                .hpke_seal(cfg(), &a.public, b"i", b"a", b"hello")
                .unwrap();
            assert_eq!(
                rust.hpke_open(cfg(), &sealed, &b.private, b"i", b"a")
                    .unwrap(),
                b"hello"
            );
            let sealed = rust
                .hpke_seal(cfg(), &a.public, b"i", b"a", b"hello")
                .unwrap();
            assert_eq!(
                lx.hpke_open(cfg(), &sealed, &a.private, b"i", b"a")
                    .unwrap(),
                b"hello"
            );

            let (enc, x) = lx
                .hpke_setup_sender_and_export(cfg(), &a.public, b"i", b"ctx", 48)
                .unwrap();
            let y = rust
                .hpke_setup_receiver_and_export(cfg(), &enc, &b.private, b"i", b"ctx", 48)
                .unwrap();
            assert_eq!(x.as_ref(), y.as_ref());
        }

        #[test]
        fn symmetric_primitives_agree() {
            let (lx, rust) = (crypto(), rc());
            let h = HashType::Sha2_384;
            for len in [0usize, 1, 111, 112, 128, 4096] {
                let data = vec![0xA5; len];
                assert_eq!(lx.hash(h, &data).unwrap(), rust.hash(h, &data).unwrap());
            }
            assert_eq!(
                lx.hmac(h, b"key", b"msg").unwrap().as_slice(),
                rust.hmac(h, b"key", b"msg").unwrap().as_slice()
            );
            assert_eq!(
                lx.hkdf_extract(h, b"salt", b"ikm").unwrap().as_slice(),
                rust.hkdf_extract(h, b"salt", b"ikm").unwrap().as_slice()
            );
            let prk = lx.hkdf_extract(h, b"salt", b"ikm").unwrap();
            assert_eq!(
                lx.hkdf_expand(h, prk.as_slice(), b"info", 100)
                    .unwrap()
                    .as_slice(),
                rust.hkdf_expand(h, prk.as_slice(), b"info", 100)
                    .unwrap()
                    .as_slice()
            );
            let (key, nonce) = ([3u8; 32], [4u8; 12]);
            let ct = lx
                .aead_encrypt(AeadType::Aes256Gcm, &key, b"plain", &nonce, b"aad")
                .unwrap();
            assert_eq!(
                ct,
                rust.aead_encrypt(AeadType::Aes256Gcm, &key, b"plain", &nonce, b"aad")
                    .unwrap()
            );
        }
    }
}
