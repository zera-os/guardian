use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::Duration;
use std::thread;
use solana_client::rpc_client::{GetConfirmedSignaturesForAddress2Config, RpcClient};
use solana_client::rpc_config::RpcTransactionConfig;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use solana_transaction_status::{option_serializer::OptionSerializer, UiTransactionEncoding};

type LogCallback = extern "C" fn(signature: *const c_char, slot: u64, logs_json: *const c_char);

/// Backfill past Solana events
/// 
/// Environment variables:
/// - BACKFILL_ENABLED: "true"/"1" to enable, anything else disables (default: disabled)
/// - BACKFILL_LIMIT: Number of past transactions to fetch (default: 100, max: 1000)
/// 
/// Returns true if backfill was performed, false if disabled or error
#[no_mangle]
pub extern "C" fn backfill_past_events(
    http_url: *const c_char,
    program_id: *const c_char,
    cb: LogCallback,
) -> bool {
    // Check if backfill is enabled via env variable
    let enabled = match std::env::var("BACKFILL_ENABLED") {
        Ok(v) => {
            let s = v.to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "y")
        }
        Err(_) => false,
    };

    if !enabled {
        return false;
    }

    // Get limit from env (default 100, max 1000)
    let limit = std::env::var("BACKFILL_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1000);

    println!("🔄 Backfill enabled: fetching up to {} past transactions", limit);

    // Validate inputs
    if http_url.is_null() || program_id.is_null() {
        eprintln!("❌ ERROR: http_url or program_id is null");
        return false;
    }

    let http = unsafe { CStr::from_ptr(http_url) }
        .to_string_lossy()
        .to_string();
    let pid = unsafe { CStr::from_ptr(program_id) }
        .to_string_lossy()
        .to_string();

    let program = match pid.parse::<Pubkey>() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ ERROR: Invalid program ID: {}", e);
            return false;
        }
    };

    // Create RPC client
    let client = RpcClient::new(http);

    // Fetch signatures
    println!("📡 Fetching signatures for program: {}", program);
    let sigs = match client.get_signatures_for_address_with_config(
        &program,
        GetConfirmedSignaturesForAddress2Config {
            before: None,
            until: None,
            limit: Some(limit),
            commitment: Some(CommitmentConfig::finalized()),
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ ERROR: Failed to fetch signatures: {}", e);
            return false;
        }
    };

    if sigs.is_empty() {
        println!("✅ No past transactions found");
        return true;
    }

    println!("📦 Found {} transactions, processing oldest to newest...", sigs.len());

    let mut processed = 0;
    let mut errors = 0;

    // Process oldest to newest (reverse order)
    for (idx, info) in sigs.iter().rev().enumerate() {
        if let Ok(sig) = info.signature.parse::<solana_sdk::signature::Signature>() {
            let cfg = RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Json),
                commitment: Some(CommitmentConfig::finalized()),
                max_supported_transaction_version: Some(0),
            };

            match client.get_transaction_with_config(&sig, cfg) {
                Ok(tx) => {
                    // Extract logs
                    let logs: Vec<String> = match tx.transaction.meta {
                        Some(meta) => match meta.log_messages {
                            OptionSerializer::Some(logs) => logs,
                            _ => Vec::new(),
                        },
                        None => Vec::new(),
                    };

                    // Convert to JSON string
                    let logs_json =
                        serde_json::to_string(&logs).unwrap_or_else(|_| "[]".to_string());
                    let sig_c = CString::new(info.signature.clone())
                        .unwrap_or_else(|_| CString::new("").unwrap());
                    let logs_c =
                        CString::new(logs_json).unwrap_or_else(|_| CString::new("[]").unwrap());

                    // Call the same callback as the live subscriber
                    cb(sig_c.as_ptr(), info.slot, logs_c.as_ptr());
                    processed += 1;

                    // Small delay to avoid overwhelming processing pipeline
                    thread::sleep(Duration::from_millis(10));

                    // Progress update every 10 transactions
                    if (idx + 1) % 10 == 0 {
                        println!("   ... processed {}/{}", idx + 1, sigs.len());
                    }
                }
                Err(e) => {
                    eprintln!(
                        "⚠️  WARNING: Failed to fetch transaction {}: {}",
                        info.signature, e
                    );
                    errors += 1;
                }
            }
        }
    }

    println!(
        "✅ Backfill complete: {} processed, {} errors",
        processed, errors
    );
    true
}

