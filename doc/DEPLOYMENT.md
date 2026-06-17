# Avatar Deployment — Phase 1 (Interactive)

Status: Draft

This document describes the current interactive deployment model for Avatar.
Phase 2 (systemd user service) and Phase 3 (login manager integration) are
future work documented in
[ARCHITECTURE.md](../../club.dwdc.keymaster/doc/ARCHITECTURE.md).

## Overview

In Phase 1, the user runs `keymaster-avatar` directly in a terminal. The
process connects to a Nostr relay, generates a transport keypair, and
displays a QR code for KeyMaster to scan. Once attached, Avatar creates
service channels and exposes local sockets for SSH and GPG clients.

The current prototype bundles Avatar and its service avatars (SSH service
avatar, GPG service avatar) into one process. In the target architecture,
Avatar exposes a single local API socket and separate service avatar
processes connect to it, each exposing its own native protocol socket.
Phase 1 validates the protocol stack end-to-end without requiring that
separation.

## Prerequisites

- A Nostr relay accessible to both Avatar and KeyMaster (e.g., strfry)
- KeyMaster running on a phone with the mnemonic loaded and an identity
  created
- The KeyMaster identity's transport public key added to Avatar's allowlist

## Start Avatar

```sh
keymaster-avatar --relay ws://relay.example.com:7777
```

Avatar connects to the relay, subscribes for incoming events, and prints a
QR code to the terminal. The QR encodes an `AvatarDescriptor` containing the
relay URL, Avatar's transport public key, and the supported services.

## Set Socket Environment Variables

The bundled prototype exposes SSH-agent and GPG-agent sockets directly:

```sh
export SSH_AUTH_SOCK=/tmp/keymaster-avatar-ssh-agent.sock
export GPG_AGENT_SOCK=/tmp/keymaster-avatar-gpg-agent.sock
```

These paths are configurable with `--agent_socket` and `--gpg_agent_socket`.

In the target architecture these sockets will be created by separate service
avatar processes, not by Avatar itself. The environment variable setup will
remain the same from the user's perspective.

## Attach KeyMaster

Scan the QR code with KeyMaster on the phone. KeyMaster sends an attach
request via the relay. Avatar verifies the KeyMaster transport identity
against its allowlist, creates a realm, and spawns service channels for each
requested service.

## Verify

```sh
# List SSH identities from the attached KeyMaster
ssh-add -l

# Test GPG signing (if OpenPGP service is active)
echo "test" | gpg --sign --armor
```

## Detach

Detach from KeyMaster on the phone when done. KeyMaster sends a detach
request via the relay. Avatar tears down the realm and all service channels.
Local agent connections are closed.

## Phase Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| 1 — Interactive | User runs Avatar in a terminal | Current |
| 2 — User service | systemd `--user` service, socket in `$XDG_RUNTIME_DIR` | Future |
| 3 — Login manager | PAM + greeter integration, attach triggers login | Future |
