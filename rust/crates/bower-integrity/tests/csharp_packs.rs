//! Parity with real C#-built packs: `bower pack build` (C# `PackArchive.Build`)
//! wrote these manifests as `CanonicalJson.Bytes` and signed them with
//! `DetachedSigner.Sign`. The fixtures are the `manifest.json` / `manifest.sig`
//! entries extracted from the C#-signed `.bowerpack` archives.

use std::path::PathBuf;

use bower_integrity::{DetachedSignature, canonical_json, key_id_from_public_key_pem, verify};

const PACKS: [&str; 3] = ["aws-security", "gcp-security", "linux-ssh-gateway"];

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/packs")
        .join(name);
    std::fs::read(path).unwrap()
}

fn public_key() -> String {
    String::from_utf8(fixture("csharp-signing.pub.pem")).unwrap()
}

fn signature(pack: &str) -> DetachedSignature {
    serde_json::from_slice(&fixture(&format!("{pack}.manifest.sig"))).unwrap()
}

#[test]
fn canonical_json_reproduces_csharp_manifest_bytes() {
    for pack in PACKS {
        let manifest = fixture(&format!("{pack}.manifest.json"));
        let parsed: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        assert_eq!(
            canonical_json::bytes_from_str(std::str::from_utf8(&manifest).unwrap()).unwrap(),
            manifest
        );
        assert_eq!(
            canonical_json::bytes(&parsed),
            manifest,
            "{pack} manifest is not byte-identical after canonicalisation"
        );
    }
}

#[test]
fn csharp_pack_signatures_verify() {
    let key = public_key();
    for pack in PACKS {
        let manifest = fixture(&format!("{pack}.manifest.json"));
        let signature = signature(pack);
        assert_eq!(signature.algorithm, "ES256");
        assert_eq!(signature.key_id, key_id_from_public_key_pem(&key).unwrap());
        assert!(verify(&manifest, &signature, [key.as_str()]), "{pack}");
    }
}

#[test]
fn tampered_manifest_or_untrusted_key_fails() {
    let key = public_key();
    let manifest = fixture("aws-security.manifest.json");
    let aws = signature("aws-security");

    let mut tampered = manifest.clone();
    let index = tampered.iter().position(|byte| *byte == b'1').unwrap();
    tampered[index] = b'2';
    assert!(!verify(&tampered, &aws, [key.as_str()]));

    let other = bower_integrity::generate_key_pair();
    assert!(!verify(&manifest, &aws, [other.public_key_pem.as_str()]));
    assert!(!verify(&manifest, &aws, std::iter::empty::<&str>()));

    // Signature belongs to another pack's manifest.
    let gcp = signature("gcp-security");
    assert!(!verify(&manifest, &gcp, [key.as_str()]));
}

#[test]
fn signature_json_round_trips_with_csharp_escaping() {
    let raw = fixture("aws-security.manifest.sig");
    let parsed = signature("aws-security");
    // C# writes `+` as `+`; bower_contracts::json reproduces the bytes.
    assert_eq!(bower_contracts::json::to_vec(&parsed).unwrap(), raw);
}
