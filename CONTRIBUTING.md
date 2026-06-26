# Contributing to git-remote-cloak

Thanks for your interest in improving git-remote-cloak. This is a security
tool: its encryption, on-disk/on-wire formats, and fail-closed behavior are
correctness-critical, so please read this guide before opening a change. For
usage and the threat model, see `README.md`. If you use an AI coding agent in
this repo, also follow `AGENTS.md`, which carries agent-specific rules.

## Ground rules

- Do not change the crypto, the on-disk format, or the on-wire format unless
  the change explicitly requires it. Such changes break interop with existing
  encrypted remotes and must be called out, never made as a side effect of a
  refactor.
- Never weaken fail-safe behavior: rollback (monotonic generation), repo-id
  pinning (trust-on-first-use), and tamper detection (AEAD) must keep failing
  closed.
- Never log, print, or commit secrets: the symmetric key, key material, or
  plaintext repository contents.

## Prerequisites

- Go 1.26+ and git.
- macOS: Xcode command line tools (`xcode-select --install`) for the cgo
  Keychain/Touch ID key backend. Linux builds are pure Go and use a key file.

## Build

- `make build` builds `bin/git-remote-cloak` and the `git-cloak` symlink.
- `make fmt` and `make vet` must be clean.

Do not pass a hand-written version to `go build`/`go install`; the version is
injected from the latest git tag via `-ldflags`.

## Test

Run tests through the `make` targets, not a bare `go test ./...` (the
integration suite refuses to run unless `TMPDIR` is under `~/tmp`).

- `make test` runs the unit suite.
- `make test-integration` runs the hermetic integration and security suites
  against real git.
- `make test-race` runs the race detector.
- `make test-darwin` runs the macOS Keychain backend (may prompt Touch ID).
- `make check` is the full gate (vet, lint, vuln, test, test-integration,
  test-darwin). Keep it green before you commit.

When fixing a bug, add a regression test that fails against the old code and
passes against the fix. Prefer reproducing failures end-to-end where the change
touches fetch/push/protocol behavior.

## Code style

- Standard Go, formatted with `gofmt`. Match the surrounding code's naming,
  comment density, and idioms; read a file before editing it.
- Start every source file with a short comment block describing what it does.
- Error handling is a contract:
  - Wrap leaf errors with context using `fmt.Errorf("...: %w", err)` (`%w`,
    never `%v`).
  - Classify domain errors with `cloakerr.New`/`cloakerr.Newf` and the right
    `Kind`.
  - Detect sentinels via `errors.As`/`errors.Is`, not direct type assertions.
  - Never silently swallow an error; check `bufio.Scanner.Err()` after a scan
    loop.
  - Fail closed on any ambiguity about integrity, identity, or rollback state.

## Commits and pull requests

- Use a concise, type-prefixed subject (`fix:`, `docs:`, `test:`), then a body
  explaining the why and any behavior or format implications. Plain ASCII, no
  decorative characters.
- Keep changes focused, and ensure `make check` passes.
- Open a pull request against `main`. Build artifacts (`bin/`, `dist/`,
  `docs/`) are gitignored and must never be committed.

## License

By contributing, you agree that your contributions are licensed under the
MIT License (see `LICENSE`).
