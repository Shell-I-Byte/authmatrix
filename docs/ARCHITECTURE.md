> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Architecture and boundaries

`cmd/authmatrix` provides a completely offline CLI. `internal/matrix` performs exact-schema input validation, rejects malformed/duplicate/ambiguous keys, and derives deterministic, redacted evidence records for each authorized observation. The CLI reads bounded regular files, emits versioned JSON, and uses nonzero exit codes for findings or errors. No HTTP transport, credential handling or scanning is included.

Linux output safety: `save_linux.go` validates and opens a directory descriptor (O_DIRECTORY|O_NOFOLLOW), confirms inode identity, and uses openat+O_EXCL for a new JSON evidence output. The parent directory may be renamed without retargeting a symlink after the descriptor is pinned. `save_other.go` preserves previous behavior on other platforms and lacks a comparable parent-race guarantee. Replacing an earlier ancestor or privileged mount configurations remain outside the verified protection.

Evidence: `authmatrix.result/v1` and `authmatrix.matrix/v1` are stable *within this candidate*, but no independently qualified ProofGraph-Security-IR adapter is claimed. ProofGraph ingestion must preserve observed-only provenance and human verification, never elevate `potential-bypass` to `confirmed` automatically. Source/package hashes are integrity checks, not publisher signatures.

## 2026-10-14 — RC9 Linux ancestor hardening
Linux now pins path traversal from `/` using `openat` with `O_PATH|O_DIRECTORY|O_NOFOLLOW` on each component, then creates output relative to the pinned parent. Unlike RC8, a symlink at an intermediate ancestor is rejected. Changes to privileged mounts or deliberate rename of the pinned directory itself are not confinement guarantees, and the non-Linux fallback is not race-safe. Existing authorized ordinary nested directories still work; symlinked ancestors are intentionally rejected. No evidence-contract changes.
