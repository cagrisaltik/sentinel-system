# Commander and Scout Agent Identity

Commander authenticates Scout in two separate steps:

1. TLS 1.3 verifies the Scout client certificate against `COMMANDER_CLIENT_CA`.
2. Commander calculates the lowercase SHA-256 fingerprint of the verified leaf certificate's DER bytes and checks the exact agent-to-fingerprint binding in `SCOUT_ALLOWED_IDENTITIES`.

The `REGISTER` message still carries the logical `agent` name. That value selects an enrollment entry; it does not establish cryptographic identity. Commander never accepts a fingerprint or public key from the Scout message. The existing DNS or SPIFFE URI SAN check also remains in place: the certificate must identify the same logical agent.

The existing TLS settings remain required: Commander uses `COMMANDER_TLS_CERT`, `COMMANDER_TLS_KEY`, and `COMMANDER_CLIENT_CA`; Scout uses `COMMANDER_URL`, `TLS_CA_FILE`, `AGENT_NAME`, `TLS_CLIENT_CERT`, and `TLS_CLIENT_KEY`. This phase adds the Commander-side `SCOUT_ALLOWED_IDENTITIES` setting.

## Enrollment

An administrator enrolls a Scout out of band after issuing and verifying its client certificate. Calculate the SHA-256 fingerprint from that certificate, remove the colons from the displayed fingerprint, and use lowercase hexadecimal. For example:

```text
openssl x509 -in scout-01-client.crt -noout -fingerprint -sha256
```

Set the matching name and fingerprint in the Commander runtime environment:

```text
SCOUT_ALLOWED_IDENTITIES=scout-01=<64-lowercase-hex-fingerprint>,scout-02=<64-lowercase-hex-fingerprint>
```

The angle-bracketed values above are placeholders; replace them with fingerprints from the certificates you have verified. The value is a comma-separated list of `agent-name=fingerprint` entries. Agent names must use letters, digits, dots, underscores, or hyphens. Commander refuses to start if the variable is empty, malformed, contains duplicate names, or binds one certificate fingerprint to multiple names.

The wire protocol is unchanged, so a Scout binary does not need a new identity field or fingerprint implementation. An existing Scout will be rejected until its exact certificate fingerprint is enrolled under its configured `AGENT_NAME` and the certificate SAN matches that name. A trusted CA certificate alone is no longer sufficient.

Set `AGENT_NAME` on each Scout to the corresponding enrolled name. The Scout certificate must also contain the existing matching DNS SAN (`scout-01` or `scout-01.sentinel.test`) or SPIFFE URI SAN (`spiffe://sentinel.test/scout-01`). Pass the Commander allowlist through the runtime environment when running a container; it is not baked into the image.

## Connection and authorization behavior

- A trusted CA certificate is not sufficient by itself. Its fingerprint must be enrolled for the claimed agent name.
- One fingerprint can be enrolled for only one agent, and one agent can have only one active fingerprint.
- A reconnect using the same name and fingerprint replaces the existing connection. Commander sends a normal WebSocket close to the old connection and removes it from task routing. A delayed cleanup from the old connection cannot remove the replacement.
- A different fingerprint for an enrolled name, an unknown fingerprint, or a fingerprint presented under another name is rejected. Rejected connections do not enter the active agent map or receive tasks.
- Task records retain both the logical agent name and the enrolled certificate fingerprint. Reports must come from the matching active connection and must pass the existing task ID, expiry, replay, target, and telemetry checks.

## Certificate rotation

Automatic certificate rotation and an administrative UI are not implemented. To rotate a Scout certificate, an administrator must verify the new certificate, explicitly replace that agent's fingerprint in `SCOUT_ALLOWED_IDENTITIES`, restart Commander, and restart the Scout with its new certificate. Do not add a second fingerprint for the same name or re-enroll a certificate without verifying it. The single-fingerprint policy requires a coordinated change and can briefly disconnect that Scout; restarting Commander drops all active connections and in-memory pending tasks.

This configuration is the current enrollment store; no agent identity table is added to MySQL. Protect Commander environment configuration as operational security data and do not commit real fingerprints or credentials to source control.
