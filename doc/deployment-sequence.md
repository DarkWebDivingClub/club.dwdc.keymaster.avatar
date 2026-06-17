# Phase 1 Interactive Deployment Sequence

This diagram shows the Phase 1 interactive flow. The current prototype
bundles Avatar and its service avatars into one process, so the SSH/GPG
protocol sockets are served directly by `keymaster-avatar`.

```mermaid
sequenceDiagram
    participant User
    participant Avatar as keymaster-avatar
    participant Relay as Nostr Relay
    participant KM as KeyMaster (phone)
    participant KV as KeyVault

    Note over User,Avatar: Startup
    User->>Avatar: keymaster-avatar --relay ws://relay:7777
    Avatar->>Avatar: Generate transport keypair
    Avatar->>Relay: Connect + subscribe (avatar pubkey)
    Avatar->>User: Display QR (relay, pubkey, services)

    Note over User,KM: Attachment
    User->>KM: Scan QR code
    KM->>Relay: NIP-44 encrypted attach request
    Relay->>Avatar: Forward event
    Avatar->>Avatar: Verify pubkey allowlist, create realm
    Avatar->>Relay: NIP-44 encrypted attach response
    Relay->>KM: Forward response

    Note over Avatar,KM: Service channel setup
    loop For each service (ssh, gpg)
        Avatar->>Relay: service.spawn request (service keypair)
        Relay->>KM: Forward
        KM->>KM: Create service keypair
        KM->>Relay: service.spawn response (service pubkey)
        Relay->>Avatar: Forward
        Avatar->>Avatar: Store service channel, subscribe
    end
    Avatar->>Avatar: Create SSH-agent + GPG-agent sockets

    Note over User,KV: Operation (SSH signing example)
    User->>Avatar: ssh-add -l (via SSH-agent socket)
    Avatar->>Relay: NIP-44 request_identities (SSH service channel)
    Relay->>KM: Forward
    KM->>KV: Derive SSH public key
    KM->>Relay: NIP-44 response (identities)
    Relay->>Avatar: Forward
    Avatar->>User: SSH-agent response (key list)

    Note over User,KV: Operation (SSH sign)
    User->>Avatar: ssh user@host (via SSH-agent socket)
    Avatar->>Relay: NIP-44 sign_request (SSH service channel)
    Relay->>KM: Forward
    KM->>KV: Sign with derived key
    KM->>Relay: NIP-44 response (signature)
    Relay->>Avatar: Forward
    Avatar->>User: SSH-agent response (signature)

    Note over User,KM: Detach
    User->>KM: Detach from phone
    KM->>Relay: NIP-44 detach request
    Relay->>Avatar: Forward
    Avatar->>Avatar: Tear down realm + service channels + sockets
    Avatar->>Relay: NIP-44 detach response
    Relay->>KM: Forward
```
