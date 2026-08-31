# Repository Instructions

These instructions apply to this repository and every subdirectory.

## Project Goal

Build a pure-Rust, embeddable replacement for Legacy iOS Kit, using upstream
commit `1ff4be07ea2946ccaeff2db60c4426488b8f6e32` as the behavioral baseline.
The public library is `legacy-ios-kit`; the reference CLI is `lik`.

## Non-Negotiable Constraints

- Do not invoke host-side shells, command-line tools, or subprocess fallbacks.
- Do not add C FFI compatibility layers or bundle host executables.
- Device payloads and binary patches are data assets, not host tools. Every
  asset must record its source, source revision, digest, purpose, and
  redistribution status.
- Do not create a license file or add Cargo license metadata until the user
  explicitly requests a licensing decision.
- Keep the public API Tokio-native and asynchronous.
- Support macOS, Linux, and Windows from the design stage. Keep platform code
  confined to the transport and mount platform adapters.
- Do not stop, restart, or reconfigure system USB services from the library.
- Do not request privilege escalation from the library. Return actionable host
  requirement errors instead.

## Architecture

- Keep dependencies one-way: core; transport, firmware, image, and services;
  restore and exploits; workflows; facade and CLI.
- Hold stable device identity across reconnects; never retain a raw USB handle
  across a device-mode transition.
- Express operations as request, resolved plan, explicit destructive consent,
  execution, and an event stream.
- Validate external input once at parser, constructor, or planning boundaries.
  Use private fields, newtypes, and enums so internal code can trust invariants.
- Introduce traits only at real I/O or replaceable implementation boundaries.
  Avoid speculative managers, plugin systems, and wrapper-only abstractions.

## Rust Style

- Use Rust 2024 and preserve the workspace MSRV.
- Prefer small modules, direct functions, explicit types, and readable data
  flow. Avoid defensive checks that duplicate established invariants.
- Use `thiserror` in every library crate. `anyhow` is allowed only in
  application crates such as `legacy-ios-kit-cli`.
- Use `tracing`; do not use `println!` or `eprintln!` for library logging.
- Libraries emit tracing events but never install a subscriber.
- Prefer `#![forbid(unsafe_code)]`. Isolate and document any unavoidable unsafe
  platform implementation in the smallest private module.
- Never log raw credentials, pairing records, ECIDs, UDIDs, nonces, tickets, or
  firmware payload bytes.

## Tracing Levels

- `error`: the operation cannot continue or manual recovery may be required.
- `warn`: recoverable degradation, retries, unsupported optional behavior, or
  a risk requiring user attention.
- `info`: operation phases, device-mode transitions, selected firmware, and
  final outcomes.
- `debug`: recipes, build identities, endpoints, cache decisions, and protocol
  branches.
- `trace`: redacted message sequencing, transfer direction, and byte counts.

## Tests

- Keep tests focused on parsers, serializers, compatibility rules, protocol
  state transitions, transcripts, and real regressions.
- Do not add tests for trivial accessors, mock every trait, or pursue a coverage
  target. Tests support design confidence; they do not drive needless APIs.
- Keep network and hardware tests opt-in. Normal CI must not require Apple
  services, firmware downloads, or connected devices.
- Run verification proportional to the change and report what was run.

## Quality Gates

- Format: `cargo fmt --all`
- Lint: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Test: `cargo test --workspace --all-features`
- MSRV check: `cargo +1.88.0 check --workspace --all-targets --all-features`
- Lefthook runs formatting followed by Clippy before every commit.

## Commit Discipline

- Commit every verified, fine-grained change using Conventional Commits.
- Use `type(scope): English imperative summary`, with types such as `feat`,
  `fix`, `refactor`, `test`, `docs`, `chore`, `build`, `ci`, and `perf`.
- Keep one coherent topic per commit. Do not combine protocol code, CLI work,
  infrastructure, or unrelated formatting.
- Every intermediate commit must at least compile for its affected scope.
- Check `git status --short` before committing and preserve unrelated user
  changes.
