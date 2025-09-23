use consensus_proof::taproot::*;

#[test]
fn test_validate_taproot_script_and_extract_key() {
    let key = [3u8; 32];
    let mut script = vec![TAPROOT_SCRIPT_PREFIX];
    script.extend_from_slice(&key);
    let valid = validate_taproot_script(&script).unwrap();
    assert!(valid);
    let extracted = extract_taproot_output_key(&script).unwrap();
    assert_eq!(extracted, Some(key));
}


