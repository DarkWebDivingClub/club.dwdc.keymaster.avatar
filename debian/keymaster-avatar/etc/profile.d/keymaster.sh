if [ -S "$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock" ]; then
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock"
fi
if [ -d "$XDG_RUNTIME_DIR/gnupg-keymaster" ]; then
    export GNUPGHOME="$XDG_RUNTIME_DIR/gnupg-keymaster"
fi
if [ -S "$XDG_RUNTIME_DIR/keymaster-nostr-sa.sock" ]; then
    export NOSTR_SA_SOCK="$XDG_RUNTIME_DIR/keymaster-nostr-sa.sock"
fi
