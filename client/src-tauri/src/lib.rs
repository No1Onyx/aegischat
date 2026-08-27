use aegis_core_crypto::{
    IdentityVault,
    compute_safety_number as compute_sn,
    EncryptedDatabase,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

#[tauri::command]
fn generate_identity() -> Result<serde_json::Value, String> {
    let vault = IdentityVault::generate_new();
    let spk = vault.generate_signed_prekey(1);
    let opks = vault.generate_one_time_prekeys(1, 10);
    let bundle = vault.build_public_bundle(&spk, &opks);

    Ok(serde_json::json!({
        "mnemonic": vault.mnemonic,
        "blind_token": vault.compute_blind_delivery_token(),
        "public_bundle": bundle,
    }))
}

#[tauri::command]
fn restore_identity(mnemonic: String) -> Result<serde_json::Value, String> {
    let vault = IdentityVault::from_mnemonic_str(&mnemonic).map_err(|e| e.to_string())?;
    let spk = vault.generate_signed_prekey(1);
    let opks = vault.generate_one_time_prekeys(1, 10);
    let bundle = vault.build_public_bundle(&spk, &opks);

    Ok(serde_json::json!({
        "mnemonic": vault.mnemonic,
        "blind_token": vault.compute_blind_delivery_token(),
        "public_bundle": bundle,
    }))
}

#[tauri::command]
fn compute_safety_number(key_a_b64: String, key_b_b64: String) -> Result<String, String> {
    let bytes_a = BASE64.decode(&key_a_b64).map_err(|_| "Invalid key A base64")?;
    let bytes_b = BASE64.decode(&key_b_b64).map_err(|_| "Invalid key B base64")?;

    if bytes_a.len() != 32 || bytes_b.len() != 32 {
        return Err("Keys must be 32 bytes".to_string());
    }

    let mut arr_a = [0u8; 32];
    let mut arr_b = [0u8; 32];
    arr_a.copy_from_slice(&bytes_a);
    arr_b.copy_from_slice(&bytes_b);

    let blocks = compute_sn(&arr_a, &arr_b);
    Ok(blocks.join(" "))
}

#[tauri::command]
fn emergency_wipe_database(db_path: String) -> Result<bool, String> {
    EncryptedDatabase::emergency_wipe(&db_path).map_err(|e| e.to_string())?;
    Ok(true)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            generate_identity,
            restore_identity,
            compute_safety_number,
            emergency_wipe_database
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
