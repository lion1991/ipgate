//! Ed25519 签名验证（agent 只验签，不持有客户端私钥）。

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use ipgate_proto::{PublicKey, Signature as ProtoSig};

/// base64（标准，无填充）。
pub(crate) const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD_NO_PAD;

fn decode_pubkey(pk: &PublicKey) -> Option<VerifyingKey> {
    let bytes = B64.decode(pk.as_str()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

fn decode_sig(sig: &ProtoSig) -> Option<Signature> {
    let bytes = B64.decode(sig.as_str()).ok()?;
    let arr: [u8; 64] = bytes.try_into().ok()?;
    Some(Signature::from_bytes(&arr))
}

/// 用客户端公钥校验对 `message` 的签名。任何解码/验签失败都返回 `false`。
pub fn verify(pubkey: &PublicKey, message: &[u8], signature: &ProtoSig) -> bool {
    let (Some(vk), Some(sig)) = (decode_pubkey(pubkey), decode_sig(signature)) else {
        return false;
    };
    vk.verify_strict(message, &sig).is_ok()
}

#[cfg(test)]
pub(crate) mod testkit {
    //! 测试辅助：从固定种子造确定性密钥并签名（无需 RNG）。
    use super::B64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use ipgate_proto::{PublicKey, Signature as ProtoSig};

    pub fn keypair(seed: u8) -> (SigningKey, PublicKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = PublicKey::from(B64.encode(sk.verifying_key().to_bytes()));
        (sk, pk)
    }

    pub fn sign(sk: &SigningKey, message: &[u8]) -> ProtoSig {
        ProtoSig::from(B64.encode(sk.sign(message).to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testkit::{keypair, sign};

    #[test]
    fn good_signature_verifies() {
        let (sk, pk) = keypair(7);
        let msg = b"hello ipgate";
        assert!(verify(&pk, msg, &sign(&sk, msg)));
    }

    #[test]
    fn tampered_message_or_wrong_key_fails() {
        let (sk, pk) = keypair(7);
        let (_, other) = keypair(9);
        let sig = sign(&sk, b"hello ipgate");
        assert!(!verify(&pk, b"HELLO ipgate", &sig)); // 改消息
        assert!(!verify(&other, b"hello ipgate", &sig)); // 换公钥
        assert!(!verify(&pk, b"hello ipgate", &ProtoSig::from("not-base64!!"))); // 烂签名
    }
}
