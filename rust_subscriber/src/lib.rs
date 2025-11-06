// Separate backfill module - does not affect existing subscriber code
pub mod backfill;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::RecvTimeoutError;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use solana_client::pubsub_client::PubsubClient;
use solana_client::rpc_client::{RpcClient, GetConfirmedSignaturesForAddress2Config};
use solana_client::rpc_config::{
    RpcTransactionLogsFilter,
    RpcTransactionLogsConfig,
    RpcTransactionConfig,
};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use solana_transaction_status::{UiTransactionEncoding, option_serializer::OptionSerializer};

type LogCallback = extern "C" fn(signature: *const c_char, slot: u64, logs_json: *const c_char);

#[no_mangle]
pub extern "C" fn rust_ffi_ping() -> u32 {
    1
}

struct Runner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}
#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
struct BridgeState {
    last_signature: Option<String>,
    last_slot: u64,
}

fn read_env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|v| {
            let s = v.to_ascii_lowercase();
            match s.as_str() {
                "1" | "true" | "yes" | "y" => Some(true),
                "0" | "false" | "no" | "n" => Some(false),
                _ => None,
            }
        })
        .unwrap_or(default)
}

fn derive_http_url_from_ws(ws: &str) -> Option<String> {
    // naive mapping: ws://host:8900 -> http://host:8899, wss -> https
    let mut url = ws.replace("wss://", "https://").replace("ws://", "http://");
    if let Some(idx) = url.rfind(':') {
        if url[idx..].starts_with(":8900") {
            url.replace_range(idx.., ":8899");
        }
    }
    Some(url)
}

fn load_state(path: &PathBuf) -> BridgeState {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return BridgeState::default(),
    };
    let mut buf = String::new();
    if f.read_to_string(&mut buf).is_ok() {
        serde_json::from_str(&buf).unwrap_or_default()
    } else {
        BridgeState::default()
    }
}

fn save_state(path: &PathBuf, state: &BridgeState) {
    if let Ok(tmp_path) = path.with_extension("tmp").into_os_string().into_string() {
        if let Ok(mut f) = File::create(&tmp_path) {
            if let Ok(s) = serde_json::to_string(state) {
                let _ = f.write_all(s.as_bytes());
                let _ = f.sync_all();
                let _ = fs::rename(tmp_path, path);
            }
        }
    }
}

fn backfill_if_needed(http_url: &str, program: &Pubkey, state_path: &PathBuf, cb: LogCallback) {
    let do_backfill = read_env_bool("BACKFILL_ON_START", false);
    if !do_backfill {
        return;
    }
    let client = RpcClient::new(http_url.to_string());
    let mut state = load_state(state_path);
    let before: Option<solana_sdk::signature::Signature> = state
        .last_signature
        .as_ref()
        .and_then(|s| s.parse().ok());
    // Pull a single page (up to 1000) before last processed; if none, take most recent few
    let sigs = match client.get_signatures_for_address_with_config(
        program,
        GetConfirmedSignaturesForAddress2Config {
            before,
            until: None,
            limit: Some(100),
            commitment: Some(CommitmentConfig::finalized()),
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("backfill get_signatures error: {e}");
            return;
        }
    };
    // Process oldest to newest
    for info in sigs.iter().rev() {
        if let Ok(sig) = info.signature.parse::<solana_sdk::signature::Signature>() {
            let cfg = RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Json),
                commitment: Some(CommitmentConfig::finalized()),
                max_supported_transaction_version: Some(0),
            };
            if let Ok(tx) = client.get_transaction_with_config(&sig, cfg) {
                let logs: Vec<String> = match tx.transaction.meta {
                    Some(meta) => match meta.log_messages {
                        OptionSerializer::Some(logs) => logs,
                        _ => Vec::new(),
                    },
                    None => Vec::new(),
                };
                let logs_json = serde_json::to_string(&logs).unwrap_or_else(|_| "[]".to_string());
                let sig_c = CString::new(info.signature.clone()).unwrap_or_else(|_| CString::new("").unwrap());
                let logs_c = CString::new(logs_json).unwrap_or_else(|_| CString::new("[]").unwrap());
                cb(sig_c.as_ptr(), info.slot, logs_c.as_ptr());
                state.last_signature = Some(info.signature.clone());
                state.last_slot = info.slot;
            }
        }
    }
    save_state(state_path, &state);
}

static RUNNERS: Lazy<Mutex<HashMap<u32, Runner>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static NEXT_ID: Lazy<Mutex<u32>> = Lazy::new(|| Mutex::new(1));

#[no_mangle]
pub extern "C" fn start_solana_logs_subscription(ws_url: *const c_char, program_id: *const c_char, cb: LogCallback) -> c_uint {
    let _ = env_logger::try_init();

    if ws_url.is_null() || program_id.is_null() {
        return 0;
    }

    let ws = unsafe { CStr::from_ptr(ws_url) }.to_string_lossy().to_string();
    let pid = unsafe { CStr::from_ptr(program_id) }.to_string_lossy().to_string();

    let program = match pid.parse::<Pubkey>() {
        Ok(p) => p,
        Err(_) => return 0,
    };

    let id = {
        let mut lock = NEXT_ID.lock();
        let id = *lock;
        *lock = lock.wrapping_add(1).max(1);
        id
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let handle = thread::spawn(move || {
        // derive state path and http url
        let state_path = std::env::var("BRIDGE_STATE_PATH")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/app/state.json"));
        let http_url = std::env::var("HTTP_URL").ok().unwrap_or_else(|| derive_http_url_from_ws(&ws).unwrap_or_else(|| "http://127.0.0.1:8899".to_string()));
        println!("HTTP URL: {}", http_url);
        // Optional one-time backfill
        backfill_if_needed(&http_url, &program, &state_path, cb);

        let mut last_state = load_state(&state_path);
        let mut since_flush = 0u32;

        let filter = RpcTransactionLogsFilter::Mentions(vec![program.to_string()]);
        let cfg = RpcTransactionLogsConfig { commitment: Some(CommitmentConfig::finalized()) };
        
        let mut backoff_ms: u64 = 500;
        let backoff_max: u64 = 30_000;

        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            match PubsubClient::logs_subscribe(&ws, filter.clone(), cfg.clone()) {
                Ok((mut _client, receiver)) => {
                    // reset backoff on successful subscribe
                    backoff_ms = 500;
                    loop {
                        if stop_clone.load(Ordering::Relaxed) {
                            break;
                        }
                        match receiver.recv_timeout(Duration::from_millis(250)) {
                            Ok(msg) => {
                                let sig_c = CString::new(msg.value.signature.clone()).unwrap_or_else(|_| CString::new("").unwrap());
                                let logs_json = serde_json::to_string(&msg.value.logs).unwrap_or_else(|_| "[]".to_string());
                                let logs_c = CString::new(logs_json).unwrap_or_else(|_| CString::new("[]").unwrap());
                                cb(sig_c.as_ptr(), msg.context.slot, logs_c.as_ptr());

                                last_state.last_signature = Some(msg.value.signature);
                                last_state.last_slot = msg.context.slot;
                                since_flush += 1;
                                if since_flush >= 10 {
                                    save_state(&state_path, &last_state);
                                    since_flush = 0;
                                }
                            }
                            Err(RecvTimeoutError::Timeout) => continue,
                            Err(err) => {
                                eprintln!("subscription error: {err}");
                                break; // resubscribe
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("subscribe error: {e}");
                }
            }
            // backoff before retry
            let sleep_ms = backoff_ms;
            backoff_ms = (backoff_ms * 2).min(backoff_max);
            let mut slept = 0u64;
            while slept < sleep_ms {
                if stop_clone.load(Ordering::Relaxed) { break; }
                std::thread::sleep(Duration::from_millis(250));
                slept += 250;
            }
        }
        // final flush
        save_state(&state_path, &last_state);
    });

    RUNNERS.lock().insert(id, Runner { stop, handle: Some(handle) });
    id
}

#[no_mangle]
pub extern "C" fn stop_solana_logs_subscription(id: c_uint) {
    let mut runners = RUNNERS.lock();
    if let Some(mut r) = runners.remove(&(id as u32)) {
        r.stop.store(true, Ordering::Relaxed);
        if let Some(h) = r.handle.take() {
            let _ = h.join();
        }
    }
}

#[no_mangle]
pub extern "C" fn stop_all_solana_logs_subscriptions() {
    let ids: Vec<u32> = RUNNERS.lock().keys().cloned().collect();
    for id in ids {
        stop_solana_logs_subscription(id);
    }
}


