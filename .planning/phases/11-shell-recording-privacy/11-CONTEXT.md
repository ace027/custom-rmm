# Phase 11: Shell recording privacy -- Context

## Phase Goal
Recordings no longer hold typed secrets in the clear: keystrokes are not recorded, files are encrypted at rest, and their size is bounded.

## Requirements Covered
- REQ-25

## What Already Exists (from prior phases)
- crates/rmm-api/src/recording.rs: Recorder{create, output, input, resize, finish} writes plain asciicast v2 to RMM_RECORDING_DIR/<client_id>/<sid>.cast (0600), Finished{rel_path, sha256, bytes}; admin download and a daily retention task (365 days) live in the same file
- crates/rmm-api/src/relay.rs calls rec.input for every browser keystroke frame and ends the session with reason recording_unavailable when the recorder fails
- tenant.shell_session has recording_path, recording_sha256, recording_bytes (migration 0006)
- chacha20poly1305 is already in the dependency tree (the agent store uses XChaCha20-Poly1305); scripts/e2e-shell.sh check 8 validates the recording
- User decision (2026-11-11): encrypt recordings at rest AND stop recording keystrokes

## Key Design Decisions
- Typed input is never recorded: Recorder::input is removed and the relay no longer passes keystrokes to the recorder; output and resize events remain (echoed characters still appear in output, as on a real terminal; non-echoed input such as passwords does not)
- New recordings are written as <sid>.cast.enc: header = magic b"RMMREC1\0" + 8-byte key id (first 8 bytes of SHA-256 of the key) + 16-byte random nonce prefix; then records of u32 big-endian ciphertext length + XChaCha20-Poly1305 ciphertext of up to 64 KiB of asciicast text, nonce = prefix || u64 big-endian record counter, associated data = sid bytes || one flag byte (0 = more, 1 = final); finish() always writes a final record so truncation is detectable
- The key is 32 random bytes read from RMM_RECORDING_KEY_FILE (64 hex chars, file mode must be 0600 on unix or loading fails); RMM_RECORDING_OLD_KEY_FILES (comma separated) are accepted for decryption only, selected by key id, which gives rotation
- No key configured: the API still starts and logs a warning, but a shell session cannot record, so the relay closes it with recording_unavailable (existing behavior). There is no plaintext fallback
- recording_sha256 and recording_bytes describe the stored (encrypted) file; the admin download decrypts while streaming and returns application/x-asciicast; a download whose authentication fails or that lacks the final record returns 500 without partial plaintext being flushed after the failure is known
- Existing plaintext .cast files stay readable: the download serves by extension (.cast as before, .cast.enc decrypted); no migration of old files
- Size limit: RMM_RECORDING_MAX_BYTES (default 67108864) of asciicast plaintext per recording; reaching it ends the session with reason recording_limit and ShellCtl::Close to the agent
- No database migration is needed

## Plan Structure
- **Plan 11-01 (Wave 1)**: Encrypted, input-free recordings with a size limit -- Stop recording keystrokes, encrypt recording files with a server-held key, bound their size, and decrypt on admin download.
- **Plan 11-02 (Wave 2)**: Recording key in the dev stack, end-to-end check and runbook -- Provision a dev recording key, wire it into compose, update the end-to-end shell check and document key custody and rotation.
