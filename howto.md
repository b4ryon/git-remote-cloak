# git-remote-cloak HOWTO

End-to-end encrypted git remotes on any git host. The host stores only
opaque blobs; your local repo stays plain git. Everything below assumes
macOS with the binaries on PATH.

## Install

```
make install        # builds and installs git-remote-cloak + git-cloak into ~/bin
git cloak version
```

Requirements: git, Go 1.26+ to build. On macOS the master key lives in the
login Keychain; on Linux in a 0600 key file.

## One-time setup, first machine

0. Generate the master key (Touch ID prompt when run from a terminal):

```
git cloak keygen
```

1. Back it up NOW to two independent places (password manager + sealed
   offline copy). The remote ciphertext plus this key is the entire
   recovery story:

```
git cloak key export
```

   Use one master key per remote. Never reuse a key across two cloak
   remotes: the encrypted state carries no repo identity, so a host could
   serve one repo's state for the other and your machines would accept it.

2. Create an empty private repo on your host (no README), then point your
   repo at it with the cloak:: scheme and push:

```
git remote add origin cloak::git@github.com:YOU/REPO.git
git push -u origin main
```

3. Verify on the host web UI: you must see ONLY `manifest.age` and
   `packs/<hex>.age`, commits authored "cloak". If you can read a filename,
   stop and investigate.

## One-time setup, second machine

0. Import the key (paste the export line):

```
git cloak key import
```

1. Clone through the helper:

```
git clone cloak::git@github.com:YOU/REPO.git
```

## Daily workflow

Plain git. Nothing else to learn:

```
git pull origin main
git add -A && git commit -m "..."
git push origin main
```

- Branches and tags work like a normal remote.
- Concurrent pushes from both machines are safe: the loser of the race
  retries automatically; a genuinely diverged branch is rejected as a
  normal non-fast-forward (pull --rebase, push again).
- Pack housekeeping (geometric consolidation) happens automatically during
  push; no scheduled maintenance is required.

## Inspect and maintain

```
git cloak status                 # generation, refs, packs, applied state
git cloak repack                 # squash remote to one pack (reachable objects only)
git cloak rekey --new-key <ref>  # re-encrypt everything under a new key
```

After `rekey`, other machines must `git cloak key import` the new key and
update `cloak.keyRef`; the old key no longer decrypts anything.

## Alarms (do not retry blindly)

- `cloak: TAMPER ALARM ...` - ciphertext failed verification or the wrong
  key is configured. The bad data was NOT applied. Check `cloak.keyRef`
  first; if the key is right, treat the remote as tampered.
- `cloak: ROLLBACK ALARM ...` - the host served an older state than this
  machine has already seen. If expected (you restored the host from a
  backup), accept once:

```
git cloak accept-rollback
```

Auth, network, and missing-repo failures are reported as such and are safe
to retry.

## Configuration (git config, per repo)

| Key | Default | Meaning |
|-----|---------|---------|
| cloak.keyRef | keychain:default (macOS), file:~/.config/cloak/keys/default (Linux) | Master key location |
| cloak.geometricFactor | 2 | Pack consolidation factor; 0 disables |
| cloak.pushRetries | 5 | Concurrent-push retry cap |
| cloak.branch | cloak | Backend branch name on the host |
| cloak.logLevel | info | Debug log level |

## Troubleshooting

- Debug log: `.git/cloak/<remote>/log` (JSON lines). Raise verbosity for
  one command with `CLOAK_LOG=debug git push origin main`.
- Local helper state is disposable: deleting `.git/cloak/` rebuilds it on
  the next fetch (rollback protection restarts as trust-on-first-use).
- Sensitive commands (keygen, key export, rekey, accept-rollback) prompt
  Touch ID only in interactive terminals; scripts and launchd jobs never
  prompt.

## Disaster recovery

With only the host ciphertext and a key backup:

```
git cloak key import          # paste the backed-up export line
git clone cloak::git@github.com:YOU/REPO.git
```

Full history, branches, and tags come back. Without the key, the remote is
permanently unreadable; that is the point.
