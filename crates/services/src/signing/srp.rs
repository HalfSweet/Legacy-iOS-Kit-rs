//! SRP-6a client proof computation as used by Apple's GrandSlam
//! authentication.
//!
//! The math follows RFC 5054 (padded `k`/`u`, `H(N) xor H(g)` in `M1`), with
//! the two Apple-specific adjustments used by corecrypto's
//! `ccsrp_client_set_noUsernameInX`: the user name is excluded from the
//! private key derivation (`x = H(s | H(":" | P))`), and the hash function is
//! SHA-256 over the RFC 5054 2048-bit group.
//!
//! The implementation is generic over the digest and group so the RFC 5054
//! Appendix B test vector (SHA-1, 1024-bit group, user name in `x`) can
//! validate the core math.

use num_bigint::BigUint;
use sha2::Digest;
use sha2::Sha256;
use thiserror::Error;

/// RFC 5054 Appendix A 2048-bit group prime; generator is 2.
const GROUP_2048_N: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4",
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60",
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF",
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907",
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861",
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB",
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
);

/// RFC 5054 Appendix A 1024-bit group prime (test vectors only).
#[cfg(test)]
const GROUP_1024_N: &str = concat!(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496",
    "EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8E",
    "F4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA",
    "9AFD5138FE8376435B9FC61D2FC0EB06E3"
);

#[derive(Clone, Debug)]
pub(crate) struct SrpGroup {
    n: BigUint,
    g: BigUint,
}

impl SrpGroup {
    fn new(n_hex: &str, g: u32) -> Self {
        Self {
            n: BigUint::parse_bytes(n_hex.as_bytes(), 16).expect("group prime is valid hex"),
            g: BigUint::from(g),
        }
    }

    /// RFC 5054 2048-bit group used by GrandSlam.
    pub(crate) fn rfc5054_2048() -> Self {
        Self::new(GROUP_2048_N, 2)
    }

    #[cfg(test)]
    fn rfc5054_1024() -> Self {
        Self::new(GROUP_1024_N, 2)
    }

    fn byte_len(&self) -> usize {
        self.n.to_bytes_be().len()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum SrpError {
    #[error("server public value fails the SRP-6a safety checks")]
    SafetyCheck,
    #[error("server session proof (M2) does not match")]
    SessionProofMismatch,
}

/// SRP-6a client state for one authentication exchange.
pub(crate) struct SrpClient<D> {
    group: SrpGroup,
    username: Vec<u8>,
    /// Exclude the user name from `x`, matching corecrypto's
    /// `ccsrp_client_set_noUsernameInX`. Apple's GrandSlam requires this.
    no_username_in_x: bool,
    a: BigUint,
    big_a: BigUint,
    session_key: Option<Vec<u8>>,
    expected_m2: Option<Vec<u8>>,
    _digest: std::marker::PhantomData<D>,
}

impl<D: Digest> SrpClient<D> {
    /// Create a client with a random 256-byte ephemeral secret.
    pub(crate) fn new(group: SrpGroup, username: &str) -> Self {
        let mut a_bytes = vec![0u8; 256];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut a_bytes);
        Self::with_ephemeral(group, username, BigUint::from_bytes_be(&a_bytes))
    }

    /// Create a client with a caller-provided ephemeral secret (tests).
    pub(crate) fn with_ephemeral(group: SrpGroup, username: &str, a: BigUint) -> Self {
        let big_a = group.g.modpow(&a, &group.n);
        Self {
            group,
            username: username.as_bytes().to_vec(),
            no_username_in_x: false,
            a,
            big_a,
            session_key: None,
            expected_m2: None,
            _digest: std::marker::PhantomData,
        }
    }

    pub(crate) const fn set_no_username_in_x(&mut self, value: bool) {
        self.no_username_in_x = value;
    }

    /// Client public value, zero-padded to the group width (corecrypto sends
    /// the exchange value at the fixed group size).
    pub(crate) fn public_value(&self) -> Vec<u8> {
        pad(&self.big_a, self.group.byte_len())
    }

    /// `k = H(N | PAD(g))` from RFC 5054.
    fn multiplier(&self) -> BigUint {
        let mut h = D::new();
        h.update(pad(&self.group.n, self.group.byte_len()));
        h.update(pad(&self.group.g, self.group.byte_len()));
        BigUint::from_bytes_be(&h.finalize())
    }

    /// `x = H(s | H([I |] ":" | P))`.
    fn private_key(&self, salt: &[u8], password: &[u8]) -> BigUint {
        let mut inner = D::new();
        if !self.no_username_in_x {
            inner.update(&self.username);
        }
        inner.update(b":");
        inner.update(password);
        let inner = inner.finalize();
        let mut outer = D::new();
        outer.update(salt);
        outer.update(inner);
        BigUint::from_bytes_be(&outer.finalize())
    }

    /// Process the server challenge, returning the client proof `M1`.
    pub(crate) fn process_challenge(
        &mut self,
        salt: &[u8],
        server_public: &[u8],
        password: &[u8],
    ) -> Result<Vec<u8>, SrpError> {
        let n = &self.group.n;
        let b = BigUint::from_bytes_be(server_public);
        if (&b % n) == BigUint::from(0u32) {
            return Err(SrpError::SafetyCheck);
        }
        // u = H(PAD(A) | PAD(B))
        let mut h = D::new();
        h.update(pad(&self.big_a, self.group.byte_len()));
        h.update(pad(&b, self.group.byte_len()));
        let u = BigUint::from_bytes_be(&h.finalize());
        if u == BigUint::from(0u32) {
            return Err(SrpError::SafetyCheck);
        }
        let x = self.private_key(salt, password);
        let k = self.multiplier();
        let v = self.group.g.modpow(&x, n);
        // S = (B - k*v) ^ (a + u*x) mod N
        let base = if b > &k * &v {
            (&b - &k * &v) % n
        } else {
            (n - ((&k * &v) - &b) % n) % n
        };
        let exponent = &self.a + &u * &x;
        let s = base.modpow(&exponent, n);
        let session_key = D::digest(s.to_bytes_be()).to_vec();
        let m1 = client_proof::<D>(
            &self.group,
            &self.username,
            salt,
            &self.big_a,
            &b,
            &session_key,
        );
        let mut h = D::new();
        h.update(self.big_a.to_bytes_be());
        h.update(&m1);
        h.update(&session_key);
        self.expected_m2 = Some(h.finalize().to_vec());
        self.session_key = Some(session_key);
        Ok(m1)
    }

    /// Verify the server proof `M2`.
    pub(crate) fn verify_session(&self, m2: &[u8]) -> Result<(), SrpError> {
        match &self.expected_m2 {
            Some(expected) if expected.as_slice() == m2 => Ok(()),
            _ => Err(SrpError::SessionProofMismatch),
        }
    }

    /// Shared session key `K`; available after `process_challenge`.
    pub(crate) fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }
}

/// `M1 = H(H(N) xor H(PAD(g)) | H(I) | s | A | B | K)` with `A`/`B`/`S`
/// minimally encoded (no padding), matching pysrp and corecrypto.
fn client_proof<D: Digest>(
    group: &SrpGroup,
    username: &[u8],
    salt: &[u8],
    a: &BigUint,
    b: &BigUint,
    session_key: &[u8],
) -> Vec<u8> {
    let hash_n = D::digest(group.n.to_bytes_be());
    let hash_g = D::digest(pad(&group.g, group.byte_len()));
    let mut h = D::new();
    h.update(
        hash_n
            .iter()
            .zip(hash_g.iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<_>>(),
    );
    h.update(D::digest(username));
    h.update(salt);
    h.update(a.to_bytes_be());
    h.update(b.to_bytes_be());
    h.update(session_key);
    h.finalize().to_vec()
}

fn pad(value: &BigUint, width: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut padded = vec![0u8; width.saturating_sub(bytes.len())];
    padded.extend_from_slice(&bytes);
    padded
}

/// Derive the GrandSlam SRP password key: PBKDF2-HMAC-SHA256 over
/// SHA-256(password), hex-encoded when the server selected `s2k_fo`.
pub(crate) fn derive_srp_password(
    password: &str,
    salt: &[u8],
    iterations: u32,
    protocol: &str,
) -> [u8; 32] {
    let digest = Sha256::digest(password.as_bytes());
    let mut derived = [0u8; 32];
    match protocol {
        "s2k" => pbkdf2::pbkdf2_hmac::<Sha256>(&digest, salt, iterations, &mut derived),
        // "s2k_fo"
        _ => {
            let mut hex_digest = [0u8; 64];
            for (i, byte) in digest.iter().enumerate() {
                hex_digest[i * 2] = b"0123456789abcdef"[usize::from(byte >> 4)];
                hex_digest[i * 2 + 1] = b"0123456789abcdef"[usize::from(byte & 0x0f)];
            }
            pbkdf2::pbkdf2_hmac::<Sha256>(&hex_digest, salt, iterations, &mut derived);
        }
    }
    derived
}

#[cfg(test)]
mod tests {
    use sha1::Sha1;

    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5054 Appendix B: verifier derivation (SHA-1, 1024-bit group,
    /// user name included in x).
    #[test]
    fn rfc5054_verifier_vector() {
        let group = SrpGroup::rfc5054_1024();
        let salt = hex("BEB25379D1A8581EB5A727673A2441EE");
        let client = SrpClient::<Sha1>::with_ephemeral(group.clone(), "alice", BigUint::from(0u32));
        let k = client.multiplier();
        assert_eq!(
            k,
            BigUint::from_bytes_be(&hex("7556AA045AEF2CDD07ABAF0F665C3E818913186F"))
        );
        let x = client.private_key(&salt, b"password123");
        assert_eq!(
            x,
            BigUint::from_bytes_be(&hex("94B7555AABE9127CC58CCF4993DB6CF84D16C124"))
        );
        let v = group.g.modpow(&x, &group.n);
        assert_eq!(
            v,
            BigUint::from_bytes_be(&hex(
                "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812\
                 9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5\
                 C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5\
                 EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78\
                 E955A5E29E7AB245DB2BE315E2099AFB"
            ))
        );
    }

    /// RFC 5054 Appendix B: full client proof against the recorded exchange.
    #[test]
    fn rfc5054_premaster_secret_vector() {
        let group = SrpGroup::rfc5054_1024();
        let salt = hex("BEB25379D1A8581EB5A727673A2441EE");
        let a = BigUint::from_bytes_be(&hex(
            "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393",
        ));
        let big_b = hex("BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011\
             BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC99\
             6C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA\
             37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE\
             EB4012B7D7665238A8E3FB004B117B58");
        let mut client = SrpClient::<Sha1>::with_ephemeral(group, "alice", a.clone());
        client
            .process_challenge(&salt, &big_b, b"password123")
            .unwrap();
        let expected_s = hex("B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D\
             233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C\
             41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F\
             3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D\
             C346D7E474B29EDE8A469FFECA686E5A");
        // The session key is H(S); recompute S independently to compare.
        let x = client.private_key(&salt, b"password123");
        let b = BigUint::from_bytes_be(&big_b);
        let u = {
            let mut h = Sha1::new();
            h.update(pad(&client.big_a, client.group.byte_len()));
            h.update(pad(&b, client.group.byte_len()));
            BigUint::from_bytes_be(&h.finalize())
        };
        assert_eq!(
            u,
            BigUint::from_bytes_be(&hex("CE38B9593487DA98554ED47D70A7AE5F462EF019"))
        );
        let k = client.multiplier();
        let v = client.group.g.modpow(&x, &client.group.n);
        let n = &client.group.n;
        let kv = &k * &v;
        let base = if b > kv {
            (&b - &kv) % n
        } else {
            (n - ((&kv - &b) % n)) % n
        };
        let s = base.modpow(&(&a + &u * &x), n);
        assert_eq!(s.to_bytes_be(), expected_s);
        assert_eq!(
            client.session_key().unwrap(),
            Sha1::digest(&expected_s).as_slice()
        );
    }

    /// RFC 5054 Appendix B: the client's public value for the fixed `a`.
    #[test]
    fn rfc5054_client_public_value() {
        let group = SrpGroup::rfc5054_1024();
        let a = BigUint::from_bytes_be(&hex(
            "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393",
        ));
        let client = SrpClient::<Sha1>::with_ephemeral(group, "alice", a);
        let expected_a = hex("61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC4\
             4352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC\
             8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44\
             BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA\
             B349EF5D76988A3672FAC47B0769447B");
        assert_eq!(client.public_value(), expected_a);
    }

    #[test]
    fn rejects_zero_server_public_value() {
        let group = SrpGroup::rfc5054_1024();
        let mut client = SrpClient::<Sha1>::new(group.clone(), "alice");
        let zero_b = group.n.to_bytes_be();
        assert_eq!(
            client.process_challenge(b"salt", &zero_b, b"password123"),
            Err(SrpError::SafetyCheck)
        );
    }
}
