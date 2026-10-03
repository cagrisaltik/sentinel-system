# Sentinel System

**Sentinel System** is a security-focused monitoring and agent management platform designed for authenticated communication between a central **Commander** and distributed **Scout Agents**.

The project is currently in **Alpha** and focuses heavily on secure agent communication, authentication, task authorization, and a strong security-oriented architecture.

> ⚠️ **Project Status: Alpha**
>
> Sentinel System is under active development and is **not production-ready yet**.

---

## 🏗️ Architecture

```text
                    ┌──────────────────────┐
                    │      Web Browser     │
                    │   Commander Panel    │
                    └──────────┬───────────┘
                               │
                         HTTPS / WSS
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
                         mTLS / WebSocket
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
- Origin validation for WebSocket connections

---

## 🛡️ Secure Agent Communication

Scout ↔ Commander communication uses:

- TLS 1.3
- Mutual TLS (mTLS)
- Client certificate authentication
- Certificate-based Agent identity
- `wss://` WebSocket connections
- Certificate chain validation
- Development PKI based on Smallstep

Current development PKI:

```text
Sentinel Root CA
       │
       ▼
Sentinel Dev CA
       │
       ├── Commander Certificate
       │
       └── Scout Certificate
```

---

# 📡 WebSocket Security

The Agent Gateway has several protections against malformed, replayed, or abusive traffic.

### Implemented

- 64 KiB WebSocket message limit
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
- Task expiration
- Maximum task lifetime
- Replay protection
- Duplicate Task ID detection
- Strict target validation
- Agent identity validation

Current maximum task lifetime:

```text
60 seconds
```

---

# 📊 Agent Telemetry

Scout Agents report execution results back to Commander.

Telemetry validation currently includes:

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

Unknown or unsupported commands are rejected.

---

# 🔑 PKI & Certificate Security

The project uses a private development PKI.

Current development environment:

```text
Smallstep CLI
Sentinel Root CA
Sentinel Dev CA
Commander Certificate
Scout Certificate
Browser Development Certificate
```

Commander and Scout certificates use certificate-based authentication rather than shared plaintext secrets.

Encrypted PKCS#8 private key support is also implemented.

---

# 🗄️ Database

Commander currently supports the MySQL-based database implementation.

Database configuration is provided through environment variables.

Sensitive credentials are not hardcoded into the application.

---

# 🧪 Validation

The current Alpha implementation has been tested with:

```bash
go test ./...
```

```text
PASS
```

Build validation:

```bash
go build ./cmd/commander
go build ./cmd/scout
```

Both Commander and Scout successfully build.

Runtime testing has also covered:

- mTLS connection
- Scout registration
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

### Listener Separation

Separate browser/API traffic from Agent traffic.

Planned architecture:

```text
Browser
   │
   │ HTTPS
   ▼
Commander Web/API
   │
   │
   │ Internal API
   │
   ▼
Agent Gateway
   │
   │ WSS + mTLS
   ▼
Scout Agents
```

Goals:

- Browser clients should not require Agent mTLS certificates
- Agent Gateway should remain strictly mTLS protected
- Separate security policies for browser and Agent traffic
- Cleaner reverse proxy integration

---

## Phase 3 — Agent Identity Hardening 🔜

Strengthen the relationship between:

```text
Agent Name
     +
Certificate Identity
     +
Public Key / Fingerprint
```

Planned protections:

- Certificate fingerprint binding
- Agent identity registration
- Duplicate identity detection
- Certificate replacement workflow
- Secure reconnect handling
- Agent revocation

---

## Phase 4 — Analyst Security 🔜

Harden the Analyst/frontend component.

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

The authorization model will be designed around **least privilege**.

---

## Phase 6 — API & Resource Protection 🔜

Expand rate limiting beyond authentication.

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

Planned events:

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

Audit records should contain sufficient context for security investigations without unnecessarily storing sensitive data.

---

## Phase 8 — PKI & Certificate Lifecycle 🔜

Move beyond the current development PKI.

Planned features:

- Certificate rotation
- Certificate expiration monitoring
- Certificate revocation
- Agent certificate enrollment
- Automated certificate renewal
- CA lifecycle management
- Production PKI architecture

---

## Phase 9 — Cryptographic Agility / PQC 🔮

Long-term goal: prepare Sentinel for post-quantum cryptography without implementing cryptographic primitives ourselves.

Goals:

- Cryptographic agility
- Algorithm negotiation
- Modern TLS configuration
- Hybrid/PQC-ready certificate architecture
- Upgrade paths for future PQC standards
- Avoid hard-coded cryptographic assumptions

> Sentinel will rely on established cryptographic libraries and standards rather than implementing custom cryptography.

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

---

# 🧭 Long-Term Security Model

The intended security model is based on several principles:

### Zero Trust

Every Agent must authenticate before communicating with Commander.

### Least Privilege

Components should receive only the permissions they require.

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

- Smallstep `step-cli`
- X.509 certificates
- ECDSA development certificates

### Frontend

- HTML
- CSS
- JavaScript
- Chart.js

### Infrastructure

- Linux / Windows development environments
- Reverse proxy compatible architecture
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

# ⚠️ Alpha Disclaimer

Sentinel System is currently an **Alpha security research and development project**.

The security architecture is actively evolving and has not yet undergone a complete independent security audit or penetration test.

Do not deploy the current Alpha release directly to production or expose the Commander service to the public Internet without additional security controls.

---

# 📜 License

License information will be added as the project approaches its first stable release.

---

## ⭐ Project Status

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
