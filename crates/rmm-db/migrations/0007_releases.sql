-- Signed release manifests are stored as trust artifacts (kind 'release'),
-- with the same (kind, seq) key and the same grants as the other kinds:
-- rmm_api inserts and reads, rmm_authd reads. msp.* tables carry no row level
-- security (they are not tenant data), so no policy change is needed.
ALTER TABLE msp.trust_artifact DROP CONSTRAINT IF EXISTS trust_artifact_kind_check;
ALTER TABLE msp.trust_artifact
    ADD CONSTRAINT trust_artifact_kind_check
    CHECK (kind IN ('manifest', 'revocations', 'techlist', 'release'));
