use dsse::{sign, verify, Ed25519Signer, Ed25519Verifier, Envelope};
use sha2::{Digest, Sha256};
use std::{env, fs, io::Write, path::Path};

fn write_new(path: &str, raw: &[u8]) -> std::io::Result<()> {
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    output.write_all(raw)?;
    output.sync_all()
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        return Err(
            "expected admit-sign RAW HOST-SEED OUTPUT | verify ENVELOPE HOST-PUBLIC OUTPUT".into(),
        );
    }
    let raw = fs::read(&args[2])?;
    let key = hex::decode(fs::read_to_string(&args[3])?.trim())?;
    if Path::new(&args[4]).exists() {
        return Err("output already exists".into());
    }
    match args[1].as_str() {
        "admit-sign" => {
            let canonical = jcs_admit::admit(&raw)?;
            let signer = Ed25519Signer::from_bytes(&key)?.with_key_id("host-selected-example");
            let envelope = sign("application/vnd.in-toto+json", &canonical, &signer)?;
            write_new(&args[4], &envelope.to_json()?)?;
            println!(
                "{}",
                serde_json::json!({"operation":"admit-sign","rawSha256":hex::encode(Sha256::digest(&raw)),"rawBytes":raw.len(),"canonicalSha256":hex::encode(Sha256::digest(&canonical)),"canonicalBytes":canonical.len(),"envelopeSha256":hex::encode(Sha256::digest(envelope.to_json()?))})
            );
        }
        "verify" => {
            let envelope = Envelope::from_json(&raw)?;
            let verifier = Ed25519Verifier::from_bytes(&key)?;
            let checked = verify(&envelope, &[&verifier], 1)?;
            if checked.payload_type != "application/vnd.in-toto+json" {
                return Err("selected payload type differs".into());
            }
            let canonical = jcs_admit::admit(&checked.payload)?;
            if canonical != checked.payload {
                return Err("verified payload is not the selected canonical form".into());
            }
            write_new(&args[4], &checked.payload)?;
            println!(
                "{}",
                serde_json::json!({"operation":"verify","envelopeSha256":hex::encode(Sha256::digest(&raw)),"verifiedPayloadSha256":hex::encode(Sha256::digest(&checked.payload)),"verifiedPayloadBytes":checked.payload.len(),"payloadType":checked.payload_type})
            );
        }
        _ => return Err("unsupported operation".into()),
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!(
            "{}",
            serde_json::json!({"byteGateDecision":"refused","reason":error.to_string()})
        );
        std::process::exit(1);
    }
}
