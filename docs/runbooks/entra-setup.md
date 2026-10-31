# Entra ID setup for technician login

The RMM API accepts Microsoft Entra ID (Azure AD) v2.0 access tokens from
technicians. The API validates the token itself (RS256 only, signature from the
tenant JWKS, `iss`, `aud`, `exp`/`nbf` with 60 s leeway) and authorizes by the
`roles` claim. Administrative routes need the app role `RMM.Admin`.

## 1. Register the API application

1. Entra admin center > Applications > App registrations > New registration.
2. Name `RMM API`, supported account types "Accounts in this organizational
   directory only", no redirect URI. Register.
3. Note the **Directory (tenant) ID** and **Application (client) ID**.

## 2. Expose an API

1. Expose an API > Application ID URI > Set. Use `api://<application-client-id>`
   (or a verified domain URI). This value is the token audience.
2. In Manifest, set `requestedAccessTokenVersion` to `2` under `api`
   (`accessTokenAcceptedVersion` in the legacy manifest). v1 tokens use a
   different issuer and are rejected.

## 3. Create the app role

1. App roles > Create app role.
2. Display name `RMM Admin`, allowed member types `Users/Groups`, value
   `RMM.Admin`, description "Administer the RMM", enable. Save.
3. Enterprise applications > `RMM API` > Users and groups > Add user/group,
   assign the technicians (or a group) to `RMM Admin`.
4. Enterprise applications > `RMM API` > Properties > "Assignment required" =
   Yes, so only assigned users can obtain tokens.

A client application (the console) that signs technicians in needs its own
registration with API permission to `RMM API` and requests the scope
`api://<application-client-id>/.default`. The resulting access token carries
`roles: ["RMM.Admin"]`.

## 4. Configure the server

| Variable | Value |
| --- | --- |
| `RMM_ENTRA_TENANT_ID` | Directory (tenant) ID. Enables Entra validation. |
| `RMM_ENTRA_AUDIENCE` | Application ID URI, exactly as in the token `aud` claim. |

The API fetches
`https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration`,
caches the JWKS for one hour and refetches at most once per 60 seconds when it
sees an unknown `kid`. The issuer is taken from the discovery document.

Trust artifact upload and agent enrollment also use:

| Variable | Meaning |
| --- | --- |
| `RMM_ROOT_PUBKEYS` | Comma-separated hex Ed25519 root public keys. |
| `RMM_ROOT_THRESHOLD` | Root signatures required (default 1). |
| `RMM_NATS_PUBLIC_URL` | NATS URL given to enrolled agents, e.g. `wss://rmm.example.com/nats`. |

## 5. Development issuer (never in production)

For local work without a tenant, the API can accept tokens signed by a local
RSA key with issuer `rmm-dev`. It is off unless `RMM_AUTH_ALLOW_DEV=1`; a
warning is logged at startup when enabled.

```sh
openssl genrsa -traditional -out dev.pem 2048
openssl rsa -in dev.pem -RSAPublicKey_out -out dev.pub.pem
export RMM_AUTH_ALLOW_DEV=1
export RMM_AUTH_DEV_PUBKEY_FILE=$PWD/dev.pub.pem   # API process
export RMM_AUTH_DEV_KEY_FILE=$PWD/dev.pem          # dev-token command
export RMM_ENTRA_AUDIENCE=api://rmm-dev
rmm-server dev-token --role RMM.Admin --sub dev-admin --ttl 3600
```

`dev-token` prints a JWT to use as `Authorization: Bearer <jwt>`. PKCS#8
(`BEGIN PRIVATE KEY`) and SPKI (`BEGIN PUBLIC KEY`) PEM files are also
accepted.

## 6. Manual check of a real login

Automated tests cover token validation against a local JWKS. Verify the real
tenant once after setup:

1. Start the API with `RMM_ENTRA_TENANT_ID` and `RMM_ENTRA_AUDIENCE` set and
   `RMM_AUTH_ALLOW_DEV` unset.
2. Obtain a token as an assigned technician, for example with the Azure CLI:
   `az account get-access-token --scope api://<application-client-id>/.default --query accessToken -o tsv`
   (the CLI must be pre-authorized as a client of the API, or use the console
   sign-in).
3. Decode it at jwt.ms and confirm `ver` is `2.0`, `aud` matches
   `RMM_ENTRA_AUDIENCE`, and `roles` contains `RMM.Admin`.
4. `curl -i -X POST https://<host>/api/v1/enrollment-tokens -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"client_id":"...","site_id":"...","expires_in_hours":24,"max_uses":1,"allow_reattach":false}'`
   should return `201`. Without the header it returns `401`; with a token
   lacking the role it returns `403`.
5. Check the audit trail has an `enrollment_token.create` row with the
   technician's object id as actor.
