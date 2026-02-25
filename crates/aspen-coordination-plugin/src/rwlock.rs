//! Reader-writer lock operations.
//!
//! State stored as JSON at `__coord:rwlock:{name}`.

use aspen_client_api::ClientRpcResponse;
use aspen_client_api::RWLockResultResponse;
use aspen_wasm_guest_sdk::host::current_time_ms;
use serde::Deserialize;
use serde::Serialize;

use crate::kv;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RWLockState {
    readers: Vec<ReaderEntry>,
    writer: Option<WriterEntry>,
    /// Monotonically increasing fencing token, incremented on each write-lock acquisition.
    #[serde(default)]
    fencing_token: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReaderEntry {
    holder_id: String,
    acquired_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WriterEntry {
    holder_id: String,
    fencing_token: u64,
    acquired_at_ms: u64,
    ttl_ms: u64,
    deadline_ms: u64,
}

fn rwlock_key(name: &str) -> String {
    format!("__coord:rwlock:{name}")
}

fn state_mode(state: &RWLockState) -> &'static str {
    if state.writer.is_some() {
        "write"
    } else if !state.readers.is_empty() {
        "read"
    } else {
        "free"
    }
}

fn rwlock_resp(state: &RWLockState) -> RWLockResultResponse {
    RWLockResultResponse {
        is_success: true,
        mode: Some(state_mode(state).to_string()),
        fencing_token: state.writer.as_ref().map(|w| w.fencing_token),
        deadline_ms: state.writer.as_ref().map(|w| w.deadline_ms),
        reader_count: Some(state.readers.len() as u32),
        writer_holder: state.writer.as_ref().map(|w| w.holder_id.clone()),
        error: None,
    }
}

fn rwlock_err() -> RWLockResultResponse {
    RWLockResultResponse {
        is_success: false,
        mode: None,
        fencing_token: None,
        deadline_ms: None,
        reader_count: None,
        writer_holder: None,
        error: None,
    }
}

fn empty_state() -> RWLockState {
    RWLockState {
        readers: Vec::new(),
        writer: None,
        fencing_token: 0,
    }
}

/// Check if a writer entry has expired.
fn writer_expired(w: &WriterEntry) -> bool {
    current_time_ms() > w.deadline_ms
}

pub fn handle_acquire_read(name: String, holder_id: String, ttl_ms: u64, timeout_ms: u64) -> ClientRpcResponse {
    let deadline = if timeout_ms > 0 {
        current_time_ms() + timeout_ms
    } else {
        u64::MAX
    };

    loop {
        let result = handle_try_acquire_read(name.clone(), holder_id.clone(), ttl_ms);
        if let ClientRpcResponse::RWLockTryAcquireReadResult(ref r) = result {
            if r.is_success {
                return ClientRpcResponse::RWLockAcquireReadResult(r.clone());
            }
        }
        if current_time_ms() > deadline {
            return ClientRpcResponse::RWLockAcquireReadResult(RWLockResultResponse {
                error: Some("read lock acquisition timed out".to_string()),
                ..rwlock_err()
            });
        }
    }
}

pub fn handle_try_acquire_read(name: String, holder_id: String, _ttl_ms: u64) -> ClientRpcResponse {
    let k = rwlock_key(&name);
    match kv::cas_loop_json::<RWLockState, _>(&k, |current| {
        let mut state = current.unwrap_or_else(empty_state);

        // Clear expired writer
        if let Some(ref w) = state.writer {
            if writer_expired(w) {
                state.writer = None;
            }
        }

        if state.writer.is_some() {
            return Err("write lock held".to_string());
        }

        if !state.readers.iter().any(|r| r.holder_id == holder_id) {
            state.readers.push(ReaderEntry {
                holder_id: holder_id.clone(),
                acquired_at_ms: current_time_ms(),
            });
        }
        Ok(state)
    }) {
        Ok(state) => ClientRpcResponse::RWLockTryAcquireReadResult(rwlock_resp(&state)),
        Err(e) => ClientRpcResponse::RWLockTryAcquireReadResult(RWLockResultResponse {
            error: Some(e),
            ..rwlock_err()
        }),
    }
}

pub fn handle_acquire_write(name: String, holder_id: String, ttl_ms: u64, timeout_ms: u64) -> ClientRpcResponse {
    let deadline = if timeout_ms > 0 {
        current_time_ms() + timeout_ms
    } else {
        u64::MAX
    };

    loop {
        let result = handle_try_acquire_write(name.clone(), holder_id.clone(), ttl_ms);
        if let ClientRpcResponse::RWLockTryAcquireWriteResult(ref r) = result {
            if r.is_success {
                return ClientRpcResponse::RWLockAcquireWriteResult(r.clone());
            }
        }
        if current_time_ms() > deadline {
            return ClientRpcResponse::RWLockAcquireWriteResult(RWLockResultResponse {
                error: Some("write lock acquisition timed out".to_string()),
                ..rwlock_err()
            });
        }
    }
}

pub fn handle_try_acquire_write(name: String, holder_id: String, ttl_ms: u64) -> ClientRpcResponse {
    let k = rwlock_key(&name);
    match kv::cas_loop_json::<RWLockState, _>(&k, |current| {
        let mut state = current.unwrap_or_else(empty_state);

        // Clear expired writer
        if let Some(ref w) = state.writer {
            if writer_expired(w) {
                state.writer = None;
            }
        }

        if state.writer.is_some() {
            return Err("write lock already held".to_string());
        }
        if !state.readers.is_empty() {
            return Err("readers hold the lock".to_string());
        }

        let now = current_time_ms();
        let token = state.fencing_token + 1;
        state.fencing_token = token;
        state.writer = Some(WriterEntry {
            holder_id: holder_id.clone(),
            fencing_token: token,
            acquired_at_ms: now,
            ttl_ms,
            deadline_ms: now + ttl_ms,
        });
        Ok(state)
    }) {
        Ok(state) => ClientRpcResponse::RWLockTryAcquireWriteResult(rwlock_resp(&state)),
        Err(e) => ClientRpcResponse::RWLockTryAcquireWriteResult(RWLockResultResponse {
            error: Some(e),
            ..rwlock_err()
        }),
    }
}

pub fn handle_release_read(name: String, holder_id: String) -> ClientRpcResponse {
    let k = rwlock_key(&name);
    match kv::cas_loop_json::<RWLockState, _>(&k, |current| {
        let mut state = current.ok_or_else(|| "rwlock not found".to_string())?;
        let before = state.readers.len();
        state.readers.retain(|r| r.holder_id != holder_id);
        if state.readers.len() == before {
            return Err(format!("reader '{holder_id}' not found"));
        }
        Ok(state)
    }) {
        Ok(state) => ClientRpcResponse::RWLockReleaseReadResult(rwlock_resp(&state)),
        Err(e) => ClientRpcResponse::RWLockReleaseReadResult(RWLockResultResponse {
            error: Some(e),
            ..rwlock_err()
        }),
    }
}

pub fn handle_release_write(name: String, holder_id: String, fencing_token: u64) -> ClientRpcResponse {
    let k = rwlock_key(&name);
    match kv::cas_loop_json::<RWLockState, _>(&k, |current| {
        let mut state = current.ok_or_else(|| "rwlock not found".to_string())?;
        match &state.writer {
            Some(w) if w.holder_id == holder_id => {
                if fencing_token != 0 && w.fencing_token != fencing_token {
                    return Err(format!(
                        "fencing token mismatch: expected {}, got {fencing_token}",
                        w.fencing_token
                    ));
                }
                state.writer = None;
                Ok(state)
            }
            Some(w) => Err(format!("write lock held by '{}', not '{holder_id}'", w.holder_id)),
            None => Err("no write lock held".to_string()),
        }
    }) {
        Ok(state) => ClientRpcResponse::RWLockReleaseWriteResult(rwlock_resp(&state)),
        Err(e) => ClientRpcResponse::RWLockReleaseWriteResult(RWLockResultResponse {
            error: Some(e),
            ..rwlock_err()
        }),
    }
}

pub fn handle_downgrade(name: String, holder_id: String) -> ClientRpcResponse {
    let k = rwlock_key(&name);
    match kv::cas_loop_json::<RWLockState, _>(&k, |current| {
        let mut state = current.ok_or_else(|| "rwlock not found".to_string())?;
        match &state.writer {
            Some(w) if w.holder_id == holder_id => {
                state.writer = None;
                if !state.readers.iter().any(|r| r.holder_id == holder_id) {
                    state.readers.push(ReaderEntry {
                        holder_id: holder_id.clone(),
                        acquired_at_ms: current_time_ms(),
                    });
                }
                Ok(state)
            }
            Some(w) => Err(format!("write lock held by '{}', not '{holder_id}'", w.holder_id)),
            None => Err("no write lock held to downgrade".to_string()),
        }
    }) {
        Ok(state) => ClientRpcResponse::RWLockDowngradeResult(rwlock_resp(&state)),
        Err(e) => ClientRpcResponse::RWLockDowngradeResult(RWLockResultResponse {
            error: Some(e),
            ..rwlock_err()
        }),
    }
}

pub fn handle_status(name: String) -> ClientRpcResponse {
    let k = rwlock_key(&name);
    match kv::get_json::<RWLockState>(&k) {
        Ok(Some(mut state)) => {
            // Clear expired writer for accurate status
            if let Some(ref w) = state.writer {
                if writer_expired(w) {
                    state.writer = None;
                }
            }
            ClientRpcResponse::RWLockStatusResult(rwlock_resp(&state))
        }
        Ok(None) => ClientRpcResponse::RWLockStatusResult(rwlock_resp(&empty_state())),
        Err(e) => ClientRpcResponse::RWLockStatusResult(RWLockResultResponse {
            error: Some(e),
            ..rwlock_err()
        }),
    }
}
