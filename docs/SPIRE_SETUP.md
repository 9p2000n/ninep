# SPIRE Environment Setup

## Overview

[SPIRE](https://spiffe.io/docs/latest/spire-about/) (SPIFFE Runtime Environment) is the production implementation of the SPIFFE specification. It manages X.509-SVID issuance, rotation, and trust bundle distribution for workloads. ninep uses SPIFFE X.509-SVIDs for mutual TLS authentication and JWT-SVIDs for capability tokens.

This document covers SPIRE setup for both **test/development** and **production** environments.

---

## Architecture

```
                        ┌────────────────────────┐
                        │      SPIRE Server      │
                        │   (CA / Registration)  │
                        └───────────┬────────────┘
                                    │ Node attestation
                        ┌───────────▼────────────┐
                        │      SPIRE Agent       │
                        │   (Workload API sock)  │
                        └──────┬──────────┬──────┘
                               │          │  Workload attestation
                    ┌──────────▼───┐  ┌───▼──────────┐
                    │ p9n-exporter │  │ p9n-importer │
                    │  SVID: /exp  │  │ SVID: /imp   │
                    └──────────────┘  └──────────────┘
```

ninep workloads retrieve SVIDs via:

1. **Workload API** (recommended) — `--spiffe-agent-socket /run/spire/agent.sock`
2. **File-based** — SPIRE Agent writes PEM to disk, ninep watches for mtime changes
3. **Static PEM** — Manual cert/key files, no rotation

---

## Test/Development Environment

### Option A: Local SPIRE (Recommended for Integration Testing)

#### Prerequisites

```bash
# Download SPIRE release
curl -sLO https://github.com/spiffe/spire/releases/download/v1.11.1/spire-1.11.1-linux-amd64-musl.tar.gz
tar xf spire-1.11.1-linux-amd64-musl.tar.gz
cd spire-1.11.1

# Or install via package manager
# Arch: yay -S spire
# macOS: brew install spiffe/tap/spire
```

#### 1. Configure SPIRE Server

Create `server.conf`:

```hcl
server {
    bind_address = "127.0.0.1"
    bind_port    = "8081"
    trust_domain = "test.local"
    data_dir     = "/tmp/spire-server/data"
    log_level    = "DEBUG"

    ca_ttl       = "24h"
    default_x509_svid_ttl = "1h"

    ca_key_type  = "ec-p256"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "/tmp/spire-server/data/datastore.sqlite3"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }

    KeyManager "memory" {
        plugin_data {}
    }
}
```

#### 2. Configure SPIRE Agent

Create `agent.conf`:

```hcl
agent {
    data_dir      = "/tmp/spire-agent/data"
    log_level     = "DEBUG"
    trust_domain  = "test.local"
    server_address = "127.0.0.1"
    server_port    = "8081"

    socket_path   = "/tmp/spire-agent/agent.sock"

    # Trust server CA on first boot (development only!)
    insecure_bootstrap = true
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {}
    }

    WorkloadAttestor "unix" {
        plugin_data {}
    }

    KeyManager "memory" {
        plugin_data {}
    }
}
```

#### 3. Start SPIRE

```bash
# Terminal 1: Start server
./bin/spire-server run -config server.conf &

# Create join token for agent
TOKEN=$(./bin/spire-server token generate -spiffeID spiffe://test.local/agent -output json | jq -r '.value')

# Terminal 2: Start agent
./bin/spire-agent run -config agent.conf -joinToken "$TOKEN" &

# Wait for agent to attest
sleep 2
```

#### 4. Register ninep Workloads

```bash
# Register exporter workload (match by UID of the process running p9n-exporter)
./bin/spire-server entry create \
    -spiffeID spiffe://test.local/ninep/exporter \
    -parentID spiffe://test.local/agent \
    -selector unix:uid:$(id -u) \
    -x509SVIDTTL 3600 \
    -jwtSVIDTTL 3600

# Register importer workload
./bin/spire-server entry create \
    -spiffeID spiffe://test.local/ninep/importer \
    -parentID spiffe://test.local/agent \
    -selector unix:uid:$(id -u) \
    -x509SVIDTTL 3600 \
    -jwtSVIDTTL 3600
```

#### 5. Run ninep with Workload API

Requires building with the `workload-api` feature:

```bash
cargo build --workspace --features workload-api

# Exporter — fetches SVID from agent socket
p9n-exporter \
    --listen [::]:5640 \
    --export /srv/shared \
    --spiffe-agent-socket /tmp/spire-agent/agent.sock

# Importer — fetches SVID from agent socket
p9n-importer \
    --exporter 127.0.0.1:5640 \
    --mount /mnt/9p \
    --spiffe-agent-socket /tmp/spire-agent/agent.sock
```

#### 6. Run ninep with File-Based SVIDs (No Workload API Feature)

Use the SPIRE Agent's `-write` flag or `spire-helper` to dump SVIDs to disk:

```bash
# Option 1: Use spire-agent api fetch x509 to write PEM files
./bin/spire-agent api fetch x509 \
    -socketPath /tmp/spire-agent/agent.sock \
    -write /tmp/svids/

# This creates:
#   /tmp/svids/svid.0.pem       (leaf cert + chain)
#   /tmp/svids/svid.0.key       (private key)
#   /tmp/svids/bundle.0.pem     (trust bundle)

# Run exporter with static files
p9n-exporter \
    --listen [::]:5640 \
    --export /srv/shared \
    --cert  /tmp/svids/svid.0.pem \
    --key   /tmp/svids/svid.0.key \
    --ca    /tmp/svids/bundle.0.pem
```

For automatic rotation with file watching, re-fetch SVIDs periodically (e.g., via cron) and ninep will detect mtime changes and hot-reload.

### Option B: rcgen (Unit/Integration Tests Only)

For tests that don't need a real SPIRE deployment, use rcgen to generate ephemeral certificates. See [RCGEN_USAGE.md](RCGEN_USAGE.md) for detailed recipes.

```bash
# Run all tests (rcgen generates certs at test time)
cargo test --workspace
```

### Option C: Docker Compose (Reproducible Local Stack)

`docker-compose.yml`:

```yaml
services:
  spire-server:
    image: ghcr.io/spiffe/spire-server:1.11.1
    command: ["-config", "/etc/spire/server.conf"]
    volumes:
      - ./spire/server.conf:/etc/spire/server.conf:ro
      - spire-server-data:/var/lib/spire/server
    ports:
      - "8081:8081"

  spire-agent:
    image: ghcr.io/spiffe/spire-agent:1.11.1
    command: ["-config", "/etc/spire/agent.conf"]
    depends_on: [spire-server]
    volumes:
      - ./spire/agent.conf:/etc/spire/agent.conf:ro
      - spire-agent-sock:/run/spire
      - /proc:/proc:ro              # for unix workload attestor
    pid: "host"                      # for PID-based attestation

  p9n-exporter:
    build: .
    command: >
      p9n-exporter
        --listen [::]:5640
        --export /srv/export
        --spiffe-agent-socket /run/spire/agent.sock
    depends_on: [spire-agent]
    volumes:
      - spire-agent-sock:/run/spire:ro
      - export-data:/srv/export

  p9n-importer:
    build: .
    command: >
      p9n-importer
        --exporter p9n-exporter:5640
        --mount /mnt/9p
        --spiffe-agent-socket /run/spire/agent.sock
    depends_on: [p9n-exporter, spire-agent]
    volumes:
      - spire-agent-sock:/run/spire:ro
    devices:
      - /dev/fuse
    cap_add:
      - SYS_ADMIN
    security_opt:
      - apparmor:unconfined

volumes:
  spire-server-data:
  spire-agent-sock:
  export-data:
```

```bash
docker compose up -d

# Register workloads (run from host or exec into spire-server)
docker compose exec spire-server spire-server entry create \
    -spiffeID spiffe://test.local/ninep/exporter \
    -parentID spiffe://test.local/agent \
    -selector docker:label:com.docker.compose.service:p9n-exporter

docker compose exec spire-server spire-server entry create \
    -spiffeID spiffe://test.local/ninep/importer \
    -parentID spiffe://test.local/agent \
    -selector docker:label:com.docker.compose.service:p9n-importer
```

---

## Production Environment

### Architecture Overview

```
                ┌─────────────────────────────────────────┐
                │            SPIRE Server Cluster         │
                │  (HA: 3+ replicas, external datastore)  │
                │                                         │
                │  Upstream CA: Vault / AWS PCA / disk    │
                │  Datastore: PostgreSQL                  │
                │  Key Manager: AWS KMS / disk            │
                └──────────┬─────────────────┬────────────┘
                           │                 │
              Node attest  │                 │  Node attest
              (k8s_psat)   │                 │  (aws_iid)
                   ┌───────▼──────┐  ┌───────▼────────┐
                   │  SPIRE Agent │  │  SPIRE Agent   │
                   │  (K8s node)  │  │ (EC2 instance) │
                   └───────┬──────┘  └───────┬────────┘
                           │                 │
                Workload   │                 │  Workload
                attest     │                 │  attest
                (k8s)      │                 │  (unix)
                   ┌───────▼──────┐  ┌───────▼─────────┐
                   │ p9n-exporter │  │  p9n-importer   │
                   │   pod/node   │  │  EC2 workload   │
                   └──────────────┘  └─────────────────┘
```

### SPIRE Server (Production)

`server.conf`:

```hcl
server {
    bind_address = "0.0.0.0"
    bind_port    = "8081"
    trust_domain = "prod.example.com"
    data_dir     = "/var/lib/spire/server"
    log_level    = "INFO"
    log_format   = "json"

    # SVID TTL — short-lived for security
    ca_ttl                 = "720h"    # 30 days
    default_x509_svid_ttl  = "1h"
    default_jwt_svid_ttl   = "5m"

    ca_key_type = "ec-p256"

    # Federation (optional — for cross-cluster trust)
    federation {
        bundle_endpoint {
            address = "0.0.0.0"
            port    = 8443
        }
    }
}

plugins {
    # ── Datastore: PostgreSQL for HA ──
    DataStore "sql" {
        plugin_data {
            database_type     = "postgres"
            connection_string = "dbname=spire host=/var/run/postgresql sslmode=verify-full"
        }
    }

    # ── Node Attestation: Choose per platform ──

    # Kubernetes (PSAT — projected service account token)
    NodeAttestor "k8s_psat" {
        plugin_data {
            clusters = {
                "prod-cluster" = {
                    service_account_allow_list = ["spire:spire-agent"]
                    kube_config_file = ""
                    audience = ["spire-server"]
                }
            }
        }
    }

    # AWS EC2 (instance identity document)
    # NodeAttestor "aws_iid" {
    #     plugin_data {
    #         account_ids_for_local_validation = ["123456789012"]
    #     }
    # }

    # ── Upstream CA: HashiCorp Vault ──
    UpstreamAuthority "vault" {
        plugin_data {
            vault_addr      = "https://vault.internal:8200"
            pki_mount_point = "pki"
            ca_cert_path    = "/etc/spire/vault-ca.pem"
            token_path      = "/etc/spire/vault-token"
        }
    }

    # Alternative: AWS Private CA
    # UpstreamAuthority "aws_pca" {
    #     plugin_data {
    #         region                  = "us-east-1"
    #         certificate_authority_arn = "arn:aws:acm-pca:..."
    #     }
    # }

    # Alternative: Disk-based CA (simplest, single-server only)
    # UpstreamAuthority "disk" {
    #     plugin_data {
    #         key_file_path  = "/etc/spire/ca-key.pem"
    #         cert_file_path = "/etc/spire/ca-cert.pem"
    #     }
    # }

    # ── Key Manager: AWS KMS (recommended for prod) ──
    KeyManager "aws_kms" {
        plugin_data {
            region = "us-east-1"
        }
    }

    # Alternative: disk (simpler, secure the filesystem)
    # KeyManager "disk" {
    #     plugin_data {
    #         keys_path = "/var/lib/spire/server/keys"
    #     }
    # }

    # ── Notifier: K8s bundle distribution ──
    Notifier "k8s_bundle" {
        plugin_data {
            namespace       = "spire"
            config_map      = "spire-bundle"
        }
    }
}
```

### SPIRE Agent (Production)

`agent.conf`:

```hcl
agent {
    data_dir       = "/var/lib/spire/agent"
    log_level      = "INFO"
    log_format     = "json"
    trust_domain   = "prod.example.com"
    server_address = "spire-server.spire.svc"
    server_port    = "8081"

    socket_path    = "/run/spire/agent.sock"

    # Trust bundle from ConfigMap (K8s) or bootstrap bundle
    trust_bundle_path = "/etc/spire/bootstrap-bundle.pem"

    # SDS (Secret Discovery Service) for Envoy sidecar integration
    # sds {
    #     default_svid_name      = "default"
    #     default_bundle_name    = "ROOTCA"
    # }
}

plugins {
    # ── Node Attestation (must match server) ──
    NodeAttestor "k8s_psat" {
        plugin_data {
            cluster = "prod-cluster"
        }
    }

    # ── Workload Attestation ──

    # Kubernetes (recommended for K8s deployments)
    WorkloadAttestor "k8s" {
        plugin_data {
            skip_kubelet_verification = false
        }
    }

    # Unix (for bare-metal / VM deployments)
    WorkloadAttestor "unix" {
        plugin_data {}
    }

    KeyManager "memory" {
        plugin_data {}
    }
}
```

### Workload Registration

#### Kubernetes Selectors

```bash
# Exporter — match by service account
spire-server entry create \
    -spiffeID spiffe://prod.example.com/ninep/exporter \
    -parentID spiffe://prod.example.com/agent/k8s-node \
    -selector k8s:ns:ninep \
    -selector k8s:sa:p9n-exporter \
    -x509SVIDTTL 3600

# Importer — match by pod label
spire-server entry create \
    -spiffeID spiffe://prod.example.com/ninep/importer \
    -parentID spiffe://prod.example.com/agent/k8s-node \
    -selector k8s:ns:ninep \
    -selector k8s:sa:p9n-importer \
    -x509SVIDTTL 3600
```

#### Unix Selectors (VMs / Bare Metal)

```bash
# Match by UID
spire-server entry create \
    -spiffeID spiffe://prod.example.com/ninep/exporter \
    -parentID spiffe://prod.example.com/agent/vm-01 \
    -selector unix:uid:1001 \
    -selector unix:gid:1001

# Match by binary path (more precise)
spire-server entry create \
    -spiffeID spiffe://prod.example.com/ninep/exporter \
    -parentID spiffe://prod.example.com/agent/vm-01 \
    -selector unix:path:/usr/local/bin/p9n-exporter
```

#### AWS Selectors

```bash
spire-server entry create \
    -spiffeID spiffe://prod.example.com/ninep/exporter \
    -parentID spiffe://prod.example.com/agent/aws \
    -selector aws:tag:role:p9n-exporter \
    -selector aws:region:us-east-1
```

### Kubernetes Deployment

#### SPIRE Server StatefulSet

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: spire-server
  namespace: spire
spec:
  replicas: 3
  selector:
    matchLabels:
      app: spire-server
  serviceName: spire-server
  template:
    metadata:
      labels:
        app: spire-server
    spec:
      serviceAccountName: spire-server
      containers:
        - name: spire-server
          image: ghcr.io/spiffe/spire-server:1.11.1
          args: ["-config", "/etc/spire/server.conf"]
          ports:
            - containerPort: 8081
              name: grpc
          volumeMounts:
            - name: config
              mountPath: /etc/spire
              readOnly: true
            - name: data
              mountPath: /var/lib/spire/server
          readinessProbe:
            exec:
              command: ["spire-server", "healthcheck"]
            initialDelaySeconds: 5
            periodSeconds: 10
      volumes:
        - name: config
          configMap:
            name: spire-server-config
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: spire-server
  namespace: spire
spec:
  clusterIP: None
  selector:
    app: spire-server
  ports:
    - port: 8081
      targetPort: grpc
```

#### SPIRE Agent DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spire-agent
  namespace: spire
spec:
  selector:
    matchLabels:
      app: spire-agent
  template:
    metadata:
      labels:
        app: spire-agent
    spec:
      serviceAccountName: spire-agent
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
        - name: spire-agent
          image: ghcr.io/spiffe/spire-agent:1.11.1
          args: ["-config", "/etc/spire/agent.conf"]
          volumeMounts:
            - name: config
              mountPath: /etc/spire
              readOnly: true
            - name: agent-socket
              mountPath: /run/spire
            - name: data
              mountPath: /var/lib/spire/agent
          livenessProbe:
            exec:
              command: ["spire-agent", "healthcheck", "-socketPath", "/run/spire/agent.sock"]
            initialDelaySeconds: 15
            periodSeconds: 30
      volumes:
        - name: config
          configMap:
            name: spire-agent-config
        - name: agent-socket
          hostPath:
            path: /run/spire
            type: DirectoryOrCreate
        - name: data
          hostPath:
            path: /var/lib/spire/agent
            type: DirectoryOrCreate
```

#### ninep Exporter Pod

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: p9n-exporter
  namespace: ninep
spec:
  replicas: 1
  selector:
    matchLabels:
      app: p9n-exporter
  template:
    metadata:
      labels:
        app: p9n-exporter
    spec:
      serviceAccountName: p9n-exporter
      containers:
        - name: exporter
          image: your-registry/p9n-exporter:latest
          args:
            - "--listen"
            - "[::]:5640"
            - "--export"
            - "/srv/export"
            - "--spiffe-agent-socket"
            - "/run/spire/agent.sock"
          ports:
            - containerPort: 5640
              protocol: UDP
              name: quic
          volumeMounts:
            - name: agent-socket
              mountPath: /run/spire
              readOnly: true
            - name: export-data
              mountPath: /srv/export
          securityContext:
            capabilities:
              add: ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER"]
      volumes:
        - name: agent-socket
          hostPath:
            path: /run/spire
            type: Directory
        - name: export-data
          persistentVolumeClaim:
            claimName: export-pvc
```

---

## Trust Federation (Cross-Cluster)

For multi-cluster deployments where exporters and importers run in different trust domains:

```bash
# Cluster A (trust domain: cluster-a.example.com) — export federation bundle
spire-server bundle show -format spiffe > cluster-a-bundle.json

# Cluster B (trust domain: cluster-b.example.com) — import Cluster A's bundle
spire-server bundle set \
    -id spiffe://cluster-a.example.com \
    -format spiffe \
    -path cluster-a-bundle.json

# And vice versa if bidirectional trust is needed
```

ninep's `TrustBundleStore` supports multiple trust domains natively — the exporter will accept importers from any domain whose CA is in the store.

---

## SVID Rotation and ninep Integration

### How Rotation Works

1. SPIRE Agent periodically re-attests with the server and obtains new SVIDs
2. Default X.509-SVID TTL is 1 hour; rotation happens at ~50% lifetime (30 min)
3. New SVIDs are delivered to workloads via the Workload API streaming RPC

### ninep Rotation Modes

| Mode | Mechanism | Downtime |
|------|-----------|----------|
| **Workload API** (`--spiffe-agent-socket`) | gRPC `FetchX509SVID` streaming RPC; `SvidSource::workload_api()` receives push updates | Zero — `SpiffeCertResolver` hot-swaps `Arc<CertifiedKey>` |
| **File watching** (`--cert --key --ca`) | `SvidSource::file_watch()` polls mtime every 30s | Zero — same `SpiffeCertResolver` hot-swap mechanism |
| **Static** | No rotation | Requires restart after SVID expires |

The `SpiffeCertResolver` (implements `rustls::server::ResolvesServerCert`) uses `Arc<RwLock<Arc<CertifiedKey>>>`:
- Background task acquires write lock, swaps the inner `Arc`
- TLS handshake acquires read lock, clones the `Arc` (non-blocking)
- Existing QUIC connections are unaffected (TLS used only at handshake time)

---

## Operational Checklist

### Test Environment

- [ ] SPIRE Server running with `join_token` attestor and `sqlite3` datastore
- [ ] SPIRE Agent running with `insecure_bootstrap = true`
- [ ] Workload entries created for exporter and importer processes
- [ ] ninep built with `--features workload-api` (or using file-based SVIDs)
- [ ] Verify: `spire-agent api fetch x509 -socketPath /tmp/spire-agent/agent.sock`

### Production Environment

- [ ] SPIRE Server HA cluster (3+ replicas) with PostgreSQL datastore
- [ ] Upstream CA configured (Vault / AWS PCA / disk)
- [ ] Key Manager using HSM/KMS (not memory)
- [ ] Node attestors match platform (k8s_psat / aws_iid / azure_msi)
- [ ] Workload attestors configured (k8s / unix)
- [ ] X.509-SVID TTL set appropriately (recommend 1h)
- [ ] Trust bundles distributed (ConfigMap for K8s, bootstrap file for VMs)
- [ ] Federation configured (if cross-cluster)
- [ ] Monitoring: SPIRE server/agent health checks, SVID expiry alerts
- [ ] ninep exporter has required capabilities (`CAP_CHOWN`, `CAP_DAC_OVERRIDE`)
- [ ] Agent socket path accessible to ninep workloads (volume mount or host path)

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `no identity found` from Workload API | Workload entry selectors don't match | Check `spire-server entry list`, verify UID/PID/label selectors |
| `certificate chain verification failed` | Trust bundle missing or stale | Re-fetch bundle: `spire-server bundle show` |
| `connection refused` on agent socket | Agent not running or wrong socket path | Check `ls -la /run/spire/agent.sock`, verify agent process |
| SVID expires, connection drops | Static mode, no rotation configured | Switch to Workload API or file-watch mode |
| `untrusted domain` in ninep logs | Remote workload's trust domain not in store | Add cross-domain trust via federation |
| Agent fails to attest | Join token expired or node attestor mismatch | Generate new token or fix attestor config |

---

## References

- [SPIFFE Specification](https://github.com/spiffe/spiffe/tree/main/standards)
- [SPIRE Documentation](https://spiffe.io/docs/latest/)
- [SPIRE Server Configuration Reference](https://spiffe.io/docs/latest/deploying/spire_server/)
- [SPIRE Agent Configuration Reference](https://spiffe.io/docs/latest/deploying/spire_agent/)
- [ninep Security Architecture](SECURITY.md)
- [rcgen Usage for Test Certificates](RCGEN_USAGE.md)
