# Windows action check (spooler restart)

Manual end-to-end check of the signed spooler action on a Windows VM. CI covers
the SCM blocks (`windows_spooler` test) but not the full path.

1. Build the release agent with the dev root:
   `RMM_ROOT_PUBKEYS=<value from deploy/.env> cargo build --release --locked -p rmm-agent`.
   Enroll it as in `windows-enroll-check.md`.
2. Pause a printer and queue a print job so `%SystemRoot%\System32\spool\PRINTERS` holds files.
3. Get the definition content id from `PUT /api/v1/catalog` (re-uploading
   `deploy/dev/trust/printing.spooler-restart.env` is idempotent) and issue it:
   `POST /api/v1/agents/<agent_id>/actions` with `{"definition_content_id":"<id>","params":{}}`.
4. Poll `GET /api/v1/action-runs/<cmd_id>` until `succeeded`. Confirm the spool
   files moved to `<state_dir>\quarantine\<cmd_id hex>\` and the Spooler service is Running.
5. Stop the Spooler (`Stop-Service Spooler`), issue the action again and record
   the precheck behaviour (status and stages in the run).
6. Record date, agent commit and result per step in the release notes.
