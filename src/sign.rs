use msgs::enums::{SignatureAlgorithm, SignatureScheme};
use util;
use untrusted;
use ring;
use ring::signature;
use ring::signature::{ECDSAKeyPair, RSAKeyPair};
use std::sync::Arc;
use key;

/// A thing that can sign a message.
pub trait Signer : Send + Sync {
    /// Choose a SignatureScheme from those offered.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<SignatureScheme>;

    /// Signs `message` using `scheme`.
    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, ()>;

    /// What kind of key we have.
    fn algorithm(&self) -> SignatureAlgorithm;
}

pub type CertChainAndSigner = (Vec<key::Certificate>, Arc<Box<Signer>>);

/// Parse `der` as any supported key encoding/type,
/// returning the first which works.
pub fn any_supported_type(der: &key::PrivateKey) -> Result<Box<Signer>, ()> {
    if let Ok(rsa) = RSASigner::new(der) {
        return Ok(Box::new(rsa));
    }

    if let Ok(ecdsa) = ECDSASigner::new(der) {
        return Ok(Box::new(ecdsa));
    }

    Err(())
}

/// A Signer for RSA-PKCS1 or RSA-PSS
pub struct RSASigner {
    key: Arc<RSAKeyPair>,
    schemes: &'static [SignatureScheme],
}

static ALL_RSA_SCHEMES: &'static [SignatureScheme] = &[
     SignatureScheme::RSA_PSS_SHA512,
     SignatureScheme::RSA_PSS_SHA384,
     SignatureScheme::RSA_PSS_SHA256,
     SignatureScheme::RSA_PKCS1_SHA512,
     SignatureScheme::RSA_PKCS1_SHA384,
     SignatureScheme::RSA_PKCS1_SHA256,
];

impl RSASigner {
    pub fn new(der: &key::PrivateKey) -> Result<RSASigner, ()> {
        RSAKeyPair::from_der(untrusted::Input::from(&der.0))
            .or_else(|_| RSAKeyPair::from_pkcs8(untrusted::Input::from(&der.0)))
            .map(|s| {
                 RSASigner {
                     key: Arc::new(s),
                     schemes: ALL_RSA_SCHEMES,
                 }
            })
            .map_err(|_| ())
    }
}

impl Signer for RSASigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<SignatureScheme> {
        util::first_in_both(self.schemes, offered)
    }

    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, ()> {
        let mut sig = vec![0; self.key.public_modulus_len()];

        let encoding: &signature::RSAEncoding = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_SHA512,
            _ => return Err(()),
        };

        let rng = ring::rand::SystemRandom::new();
        let mut signer = try!(signature::RSASigningState::new(self.key.clone()).map_err(|_| ()));

        signer.sign(encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| ())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

/// A Signer for ECDSA
pub struct ECDSASigner {
    key: Arc<ECDSAKeyPair>,
    schemes: &'static [SignatureScheme],
}

static ALL_ECDSA_SCHEMES: &'static [SignatureScheme] = &[
     SignatureScheme::ECDSA_NISTP384_SHA384,
     SignatureScheme::ECDSA_NISTP256_SHA256,
];

impl ECDSASigner {
    pub fn new(der: &key::PrivateKey) -> Result<ECDSASigner, ()> {
        ECDSAKeyPair::from_pkcs8(untrusted::Input::from(&der.0))
            .map(|s| {
                 ECDSASigner {
                     key: Arc::new(s),
                     schemes: ALL_ECDSA_SCHEMES,
                 }
            })
            .map_err(|_| ())
    }
}

impl Signer for ECDSASigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<SignatureScheme> {
        util::first_in_both(self.schemes, offered)
    }

    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, ()> {
        let mut sig = vec![0; self.key.public_modulus_len()];

        let alg: &signature::ECDSASigningAlgorithm = match scheme {
            SignatureScheme::ECDSA_NISTP384_SHA384 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            SignatureScheme::ECDSA_NISTP256_SHA256 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            _ => return Err(()),
        };

        let rng = ring::rand::SystemRandom::new();
        let mut signer = try!(signature::ECDSASigningState::new(self.key.clone())
                              .map_err(|_| ()));

        signer.sign(encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| ())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}
