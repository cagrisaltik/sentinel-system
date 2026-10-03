# Sentinel System

**Sentinel System** is a security-focused monitoring and agent management platform designed for authenticated communication between a central **Commander** and distributed **Scout Agents**.

The project is currently in **Alpha** and focuses on secure agent communication, authentication, task authorization, telemetry validation, and a defense-in-depth security architecture.

> ⚠️ **Project Status: Alpha**
>
> Sentinel System is under active development and is **not production-ready**.

---

## 🏗️ Architecture

```text
                    ┌──────────────────────┐
                    │      Web Client      │
                    │   Commander Panel   │
                    └──────────┬───────────┘
                               │
                            HTTPS
                               │
                    ┌──────────▼───────────┐
                    │      Commander       │
                    │                      │
                    │ Authentication       │
                    │ Session Management   │
                    │ Task Scheduler       │
                    │ Agent Gateway        │
                    └──────────┬───────────┘
                               │
                         WSS + mTLS
                               │
              ┌────────────────┴────────────────┐
              │                                 │
      ┌───────▼────────┐               ┌────────▼───────┐
      │   Scout Agent  │               │   Scout Agent  │
      │                │               │                 │
      │ Task Execution │               │ Task Execution  │
      │ Telemetry      │               │ Telemetry       │
      └────────────────┘               └─────────────────┘
                               │
                         ┌─────▼─────┐
                         │ Database  │
                         └───────────┘
```

> The current Alpha architecture is evolving. Browser/API and Agent traffic separation is planned as part of the network architecture hardening phase.

---

# ✨ Current Features

## 🔐 Authentication & Sessions

- User authentication
- bcrypt password hashing
- Login rate limiting
- Login failure delay
- Session expiration
- Secure cookie configuration
- HTTP request body size limits
- WebSocket origin validation

---

## 🛡️ Secure Agent Communication

Scout ↔ Commander communication uses:

- TLS 1.3
- Mutual TLS (mTLS)
- Certificate-based Agent authentication
- Secure WebSocket (`wss://`)
- Certificate chain validation
- Short-lived authenticated tasks

The system is designed so that an Agent must establish a trusted cryptographic identity before communicating with Commander.

---

# 📡 WebSocket Security

The Agent Gateway includes multiple protections against malformed, oversized, replayed, or abusive traffic.

### Implemented

- WebSocket message size limits
- Read deadlines
- Write deadlines
- Pong/keepalive handling
- Concurrent connection state protection
- Safe concurrent WebSocket writes
- Unknown message type rejection
- Agent identity validation
- Telemetry validation

---

# 🎯 Task Authorization

Tasks sent to Scout Agents contain security metadata.

Example:

```json
{
  "type": "PING_ISTEGI",
  "task_id": "uuid",
  "target": "example.com",
  "agent": "scout-01",
  "issued_at": "...",
  "expires_at": "..."
}
```

### Implemented protections

- Unique Task IDs
- Task ownership validation
- Task timestamp validation
- Automatic task expiration
- Replay protection
- Duplicate Task ID detection
- Strict target validation
- Agent identity validation

Tasks are intentionally short-lived to reduce the impact of replayed or delayed commands.

---

# 📊 Agent Telemetry

Scout Agents report execution results back to Commander.

Telemetry validation includes:

- CPU usage
- RAM usage
- Disk usage
- HTTP status
- Execution time
- Agent identity
- Task ID

Example:

```text
Scout
  │
  ├── Execute Task
  │
  └── RAPOR
        │
        ├── Task ID
        ├── Agent
        ├── Target
        ├── Status
        ├── Time
        └── System Metrics
```

Commander validates received telemetry before processing it.

---

# ⚙️ Scout Agent

Scout is the lightweight agent responsible for executing authorized monitoring tasks.

Current capabilities include:

- Secure Commander connection
- mTLS authentication
- Agent registration
- Task validation
- Target validation
- Ping execution
- Telemetry collection
- Result reporting
- Automatic reconnect handling

Unsupported or unknown commands are rejected.

---

# 🔑 Cryptography & PKI

Sentinel uses standard cryptographic protocols and certificate-based authentication rather than application-level custom cryptography.

The current development environment uses a private certificate authority hierarchy for:

- Commander authentication
- Scout authentication
- Certificate chain validation
- Local development

Encrypted PKCS#8 private key support is also implemented.

> Private keys, credentials, certificates containing sensitive material, and environment secrets must never be committed to the repository.

---

# 🗄️ Database

Commander uses a database-backed architecture for:

- Users
- Agents
- Targets
- Logs
- Monitoring results

Database credentials are supplied through environment-based configuration.

Sensitive credentials are not hardcoded into the application.

---

# 🧪 Validation

The current Alpha implementation has been validated with:

```bash
go test ./...
```

Build validation:

```bash
go build ./cmd/commander
go build ./cmd/scout
```

Runtime testing has covered:

- mTLS connection
- Agent registration
- Task execution
- Telemetry reporting
- Agent disconnect
- Agent reconnect
- WebSocket connection lifecycle

---

# 🚧 Roadmap

Sentinel System is being developed incrementally with security as a primary design goal.

## Phase 1 — Agent Gateway Hardening ✅

- [x] TLS 1.3
- [x] Mutual TLS
- [x] Secure WebSocket (`wss://`)
- [x] WebSocket message limits
- [x] Read/write deadlines
- [x] Pong/keepalive handling
- [x] Task IDs
- [x] Task expiration
- [x] Replay protection
- [x] Agent identity validation
- [x] Telemetry validation
- [x] Target validation
- [x] Concurrent WebSocket state protection

---

## Phase 2 — Network Architecture Hardening 🔄

Separate browser/API traffic from Agent traffic.

Planned architecture:

```text
Web Client
    │
    │ HTTPS
    ▼
Commander Web/API
    │
    │ Internal Application Layer
    ▼
Agent Gateway
    │
    │ WSS + mTLS
    ▼
Scout Agents
```

Goals:

- Browser clients should not require Agent authentication certificates
- Agent Gateway should remain strictly mTLS protected
- Separate security policies for browser and Agent traffic
- Cleaner reverse-proxy integration
- Reduced attack surface

---

## Phase 3 — Agent Identity Hardening 🔜

Strengthen the relationship between:

```text
Agent Identity
      +
Certificate Identity
      +
Cryptographic Key Identity
```

Planned protections:

- Certificate fingerprint binding
- Strong Agent identity registration
- Duplicate identity detection
- Certificate replacement workflow
- Secure reconnect handling
- Agent revocation

---

## Phase 4 — Analyst Security 🔜

Further harden the Analyst/frontend layer.

Planned work:

- Authentication integration
- Secure session handling
- CSP hardening
- CSRF protection where applicable
- API authorization
- Input validation
- Output encoding
- Secure error handling
- Rate limiting
- Secure export handling

---

## Phase 5 — Authorization & RBAC 🔜

Introduce role-based access control.

Planned roles:

```text
Admin
Operator
Viewer
```

Potential permissions:

```text
agents.read
agents.manage
tasks.create
tasks.cancel
logs.read
reports.export
users.manage
system.manage
```

The authorization model will follow the principle of **least privilege**.

---

## Phase 6 — API & Resource Protection 🔜

Expand rate limiting and resource protection beyond authentication.

Planned protections:

- API rate limiting
- Per-user limits
- Per-IP limits
- Agent connection limits
- Task creation limits
- Export limits
- Request body limits
- Resource exhaustion protection

---

## Phase 7 — Audit Logging 🔜

Introduce a dedicated security audit trail.

Planned events include:

- User login
- Failed login
- Logout
- User creation
- Permission changes
- Agent registration
- Agent authentication
- Agent revocation
- Task creation
- Task execution
- Task failure
- Configuration changes
- Certificate operations

Audit records will be designed to provide useful security context without unnecessarily storing sensitive information.

---

## Phase 8 — PKI & Certificate Lifecycle 🔜

Move beyond the current development PKI model.

Planned features:

- Certificate rotation
- Certificate expiration monitoring
- Certificate revocation
- Agent certificate enrollment
- Automated certificate renewal
- CA lifecycle management
- Production PKI architecture

---

## Phase 9 — Cryptographic Agility & PQC Readiness 🔮

Long-term goal: prepare Sentinel for post-quantum cryptography without implementing custom cryptographic primitives.

Goals:

- Cryptographic agility
- Algorithm negotiation
- Modern TLS configuration
- Hybrid/PQC-ready architecture
- Upgrade paths for future standards
- Avoid hard-coded cryptographic assumptions

> Sentinel will rely on established cryptographic libraries, protocols, and standards rather than implementing custom cryptography.

---

## Phase 10 — Production Hardening 🔮

Before production deployment:

- Non-root containers
- Minimal container images
- Secret management
- Health/readiness endpoints
- Structured logging
- Production log levels
- Security headers
- Backup strategy
- Database hardening
- Monitoring
- Alerting
- Resource limits
- Secure deployment documentation
- Independent security testing

---

# 🧭 Security Principles

Sentinel is designed around several core security principles.

### Zero Trust

Every Agent must authenticate before communicating with Commander.

### Least Privilege

Components and users should receive only the permissions they require.

### Defense in Depth

Security should not depend on a single control.

```text
TLS
 ↓
mTLS
 ↓
Agent Identity
 ↓
Authorization
 ↓
Task Validation
 ↓
Replay Protection
 ↓
Input Validation
 ↓
Audit Logging
```

### Secure by Default

Security controls should be enabled by default rather than requiring operators to manually enable them.

### Cryptographic Agility

The system should be able to adopt stronger cryptographic algorithms as standards evolve.

---

# 🛠️ Technology Stack

### Backend

- Go
- WebSocket
- TLS 1.3
- mTLS
- bcrypt
- MySQL

### PKI

- Smallstep
- X.509 certificates
- Standard cryptographic primitives

### Frontend

- HTML
- CSS
- JavaScript
- Chart.js

### Infrastructure

- Linux / Windows development environments
- Reverse-proxy compatible architecture
- Docker support under development

---

# 📁 Project Structure

```text
sentinel-system/
│
├── cmd/
│   ├── commander/
│   │   └── main.go
│   │
│   └── scout/
│       └── main.go
│
├── internal/
│   └── models/
│       └── message.go
│
├── web/
│   └── commander/
│
├── go.mod
├── go.sum
└── README.md
```

---

# ⚠️ Security Notice

Sentinel System is currently an **Alpha security research and development project**.

The security architecture is actively evolving and has **not yet undergone a complete independent security audit or penetration test**.

The current Alpha release should not be considered production-ready.

Do not expose the Commander service directly to the public Internet without appropriate additional security controls and deployment hardening.

If you discover a security vulnerability, please report it responsibly rather than publicly disclosing exploitation details before a fix is available.

---

# 📜 License

License information will be added before the first stable release.

---

# ⭐ Project Status

```text
Version: 0.1.0-alpha

Commander       ███████░░░  Development
Scout           ████████░░  Development
Agent Security  ████████░░  Active Hardening
Analyst         █████░░░░░  Development
RBAC            ██░░░░░░░░  Planned
Audit Logging   ██░░░░░░░░  Planned
PKI Lifecycle   ██░░░░░░░░  Planned
PQC Readiness   █░░░░░░░░░  Long-term
Production      ██░░░░░░░░  Not Ready
```

---

**Sentinel System — Security first, by design.**
