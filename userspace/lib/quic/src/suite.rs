// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The TLS 1.3 cipher suites with their QUIC packet protection.
//!
//! The rustls-rustcrypto provider offers the three TLS 1.3 suites with
//! `quic: None` (its own `quic` module is a stub), and rustls refuses a QUIC
//! handshake on a suite without one. The suites here are the provider's, field
//! for field, with the QUIC [`quic::Algorithm`] added: the packet protection
//! (RFC 9001 section 5.3) is the suite's AEAD with the nonce `iv XOR packet
//! number`, and the header protection (section 5.4) is AES-ECB or the ChaCha20
//! block function over a 16-byte sample of the ciphertext. All of it is the
//! RustCrypto crates the provider is built on; nothing else is linked.

use std::sync::{Arc, OnceLock};

use aes::cipher::BlockEncrypt;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::crypto::CryptoProvider;
use rustls::quic;
use rustls::{CipherSuite, CipherSuiteCommon, Error, SupportedCipherSuite, Tls13CipherSuite};

/// Bytes of the AEAD tag of every QUIC suite.
const TAG: usize = 16;
/// Bytes of the ciphertext sample header protection reads.
const SAMPLE: usize = 16;

/// A packet protection key: the AEAD and the static IV.
struct Packet<A> {
    aead: A,
    iv: Iv,
    /// RFC 9001 section 6.6: packets one key may seal, and failures it may see
    /// before the connection must be abandoned.
    confidentiality: u64,
    integrity: u64,
}

impl<A: AeadInPlace + Send + Sync> quic::PacketKey for Packet<A> {
    fn encrypt_in_place(&self, packet_number: u64, header: &[u8], payload: &mut [u8]) -> Result<quic::Tag, Error> {
        let nonce = Nonce::new(&self.iv, packet_number).0;
        let tag = self
            .aead
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), header, payload)
            .map_err(|_| Error::EncryptError)?;
        Ok(quic::Tag::from(tag.as_slice()))
    }

    fn decrypt_in_place<'a>(&self, packet_number: u64, header: &[u8], payload: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let plain = payload.len().checked_sub(TAG).ok_or(Error::DecryptError)?;
        let nonce = Nonce::new(&self.iv, packet_number).0;
        let (data, tag) = payload.split_at_mut(plain);
        self.aead
            .decrypt_in_place_detached(GenericArray::from_slice(&nonce), header, data, GenericArray::from_slice(tag))
            .map_err(|_| Error::DecryptError)?;
        Ok(&payload[..plain])
    }

    fn tag_len(&self) -> usize {
        TAG
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity
    }
}

/// Where the 5-byte header protection mask comes from.
trait Mask: Send + Sync {
    fn mask(&self, sample: &[u8]) -> [u8; 5];
}

/// AES-ECB over the sample (section 5.4.3).
struct AesMask<C>(C);

impl<C: BlockEncrypt + Send + Sync> Mask for AesMask<C> {
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        let mut block = GenericArray::clone_from_slice(sample);
        self.0.encrypt_block(&mut block);
        [block[0], block[1], block[2], block[3], block[4]]
    }
}

/// ChaCha20 with the block counter and nonce taken from the sample (section 5.4.4).
struct ChaChaMask([u8; 32]);

impl Mask for ChaChaMask {
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
        let mut c = chacha20::ChaCha20::new(GenericArray::from_slice(&self.0), GenericArray::from_slice(&sample[4..16]));
        c.seek(u64::from(counter) * 64);
        let mut out = [0u8; 5];
        c.apply_keystream(&mut out);
        out
    }
}

struct Header<M>(M);

impl<M: Mask> Header<M> {
    /// Section 5.4.1: the same XOR masks and unmasks; only which bits of the
    /// first byte say how long the packet number is differs (the masked ones are
    /// read after they are unmasked).
    fn xor(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8], masked: bool) -> Result<(), Error> {
        if sample.len() != SAMPLE {
            return Err(Error::General("header protection sample has the wrong length".into()));
        }
        let mask = self.0.mask(sample);
        let (first_mask, pn_mask) = mask.split_first().expect("a 5-byte mask");
        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }
        let bits = if *first & 0x80 != 0 { 0x0f } else { 0x1f };
        let plain_first = if masked { *first ^ (first_mask & bits) } else { *first };
        let pn_len = usize::from(plain_first & 0x03) + 1;
        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }
        Ok(())
    }
}

impl<M: Mask> quic::HeaderProtectionKey for Header<M> {
    fn encrypt_in_place(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) -> Result<(), Error> {
        self.xor(sample, first, packet_number, false)
    }

    fn decrypt_in_place(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) -> Result<(), Error> {
        self.xor(sample, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        SAMPLE
    }
}

/// AES-128-GCM, the suite QUIC's Initial packets use.
struct Aes128Quic;
/// ChaCha20-Poly1305.
struct ChaChaQuic;

impl quic::Algorithm for Aes128Quic {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        let aead = aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).expect("a 16-byte key");
        Box::new(Packet { aead, iv, confidentiality: 1 << 23, integrity: 1 << 52 })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(Header(AesMask(aes::Aes128::new_from_slice(key.as_ref()).expect("a 16-byte key"))))
    }

    fn aead_key_len(&self) -> usize {
        16
    }
}

impl quic::Algorithm for ChaChaQuic {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        let aead = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("a 32-byte key");
        Box::new(Packet { aead, iv, confidentiality: 1 << 62, integrity: 1 << 36 })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        let mut k = [0u8; 32];
        k.copy_from_slice(key.as_ref());
        Box::new(Header(ChaChaMask(k)))
    }

    fn aead_key_len(&self) -> usize {
        32
    }
}

use aes_gcm::KeyInit;

/// `suite` (one of the provider's TLS 1.3 suites) with `alg` as its QUIC
/// protection. The suite lives for the whole program, like the provider's own.
fn with_quic(suite: SupportedCipherSuite, alg: &'static dyn quic::Algorithm) -> SupportedCipherSuite {
    // Only a build that also enables rustls' tls12 feature has the other variant.
    #[allow(irrefutable_let_patterns)]
    let SupportedCipherSuite::Tls13(base) = suite else { unreachable!("the TLS 1.3 constants of the provider") };
    SupportedCipherSuite::Tls13(Box::leak(Box::new(Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        hkdf_provider: base.hkdf_provider,
        aead_alg: base.aead_alg,
        quic: Some(alg),
    })))
}

/// The two suites, with QUIC protection. AES-128-GCM is required (RFC 9001: the
/// Initial packets of every connection use it, and quinn-proto derives their keys
/// from it). ChaCha20-Poly1305 is the other: both ends of this link are this
/// code, so there is no reason to offer AES-256-GCM as a suite as well.
fn suites() -> (SupportedCipherSuite, SupportedCipherSuite) {
    (
        with_quic(rustls_rustcrypto::TLS13_AES_128_GCM_SHA256, &Aes128Quic),
        with_quic(rustls_rustcrypto::TLS13_CHACHA20_POLY1305_SHA256, &ChaChaQuic),
    )
}

/// The provider with `cipher_suites` and a key provider that cannot hold an RSA private key: `deny.toml`
/// ignores RUSTSEC-2023-0071 (Marvin) on the ground that no RSA private-key operation is reachable, and the
/// provider's own loader tries RSA first (`azos_tls::NoRsaKeys` is the one loader that does not, shared with
/// the TLS library). The `canary-rsa-keys` build keeps the provider's loader.
fn build(cipher_suites: Vec<SupportedCipherSuite>) -> Arc<CryptoProvider> {
    let p = CryptoProvider { cipher_suites, ..rustls_rustcrypto::provider() };
    #[cfg(not(feature = "canary-rsa-keys"))]
    let p = CryptoProvider { key_provider: &azos_tls::NoRsaKeys, ..p };
    Arc::new(p)
}

/// The rustcrypto provider with QUIC-capable TLS 1.3 suites, in the order this
/// ISA wants: ChaCha20-Poly1305 first on riscv64, whose baseline has no AES
/// instructions (the AES here is the constant-time bitsliced code, several
/// times slower than ChaCha20 in software); AES-128-GCM first elsewhere (the
/// `aes` crate uses the AES instructions of aarch64 and x86_64 when the CPU has
/// them). The Initial packets use AES-128-GCM whatever comes first. Built once.
pub fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| {
        let (aes, chacha) = suites();
        build(if cfg!(target_arch = "riscv64") { vec![chacha, aes] } else { vec![aes, chacha] })
    })
    .clone()
}

/// The provider offering only `suite` (plus AES-128-GCM for the Initial
/// packets when `suite` is the other one, which the peer never negotiates):
/// the tests use it to run a handshake on each suite.
pub fn provider_only(suite: CipherSuite) -> Arc<CryptoProvider> {
    let (aes, chacha) = suites();
    build(if suite == CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 { vec![chacha, aes] } else { vec![aes] })
}

/// The suite whose id is [`CipherSuite::TLS13_AES_128_GCM_SHA256`], as the Initial packets use it.
pub(crate) fn initial_suite(p: &CryptoProvider) -> Option<quic::Suite> {
    p.cipher_suites.iter().find_map(|cs| match (cs.suite(), cs.tls13()) {
        (CipherSuite::TLS13_AES_128_GCM_SHA256, Some(s)) => s.quic_suite(),
        _ => None,
    })
}
