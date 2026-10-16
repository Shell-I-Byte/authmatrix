> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Architecture and threat model

`cmd/authmatrix` loads a bounded, regular, non-symlink JSON file and calls `internal/matrix.Decode` and `Evaluate` with no network operations. A strict parser rejects malformed UTF-8, ambiguous duplicate and noncanonical/case-folded JSON object keys at any level, trailing tokens, unknown fields, invalid scope, oversized matrices and invalid HTTP codes. Results are deterministic, sorted by anonymized case identifier digests, and written to a new 0600 file (exclusive create) or stdout.

Threats considered: forged terminal logs from untrusted filenames/flags (generic errors); invalid JSON aliases/duplicate fields (rejected); accidental overwrite of previous evidence (O_EXCL); secret leakage (do not echo input case identifiers, scope labels, bodies, tokens); unauthenticated or unauthorized observations (must be attested). Residual risks: operator dishonesty, filesystem races from directory replacement, potential hash dictionary attacks against low-entropy IDs, unverified HTTP response provenance, no independent actual access-control testing. For sensitive identifiers, anonymize before creating the input; SHA-256 is not encryption.

RC2 additionally rejects case-insensitive aliases accepted by the legacy Go
`encoding/json` decoder, avoiding mismatches between JSON Schema interpretation
and Go struct interpretation (notably `approved:false` + `Approved:true`).
Direct FIFOs and symlinks were already refused in RC1, but a concurrent
regular-file/FIFO exchange could cause RC2 to block *between* `Lstat` and `Open`.
RC3 uses Unix `O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC` to avoid this FIFO-open
blockage, followed by `fstat` and identity checks of the opened file. A local
Linux `renameat2(RENAME_EXCHANGE)` test reproduced RC2 hangs and then verified
RC3 survives repeated attempts. This is **not** full protection against hostile
parent-directory mutations, content changes to a regular file, or races on
other operating systems. No claim of native Windows or macOS runtime testing.


## 2026-10-13 — Linux output parent race

The RC7 writer performed `Lstat` on a parent path and later used a fresh absolute pathname in `os.OpenFile`. Concurrent rename-exchange of a directory and a symlink could redirect report output to another directory. RC8 on Linux uses `openat`/`unlinkat` against one pinned parent directory descriptor and checks opened inode identity. It is a **partial mitigation**, not a guarantee that all ancestor components or filesystem mountpoints are immutable. On non-Linux systems, the fallback retains `Lstat`+`O_EXCL` and **must not be claimed race-safe**. Existing filenames remain non-overwritable under ordinary local filesystem semantics.

## 2026-10-14 — RC9 Linux ancestor hardening
Linux now pins path traversal from `/` using `openat` with `O_PATH|O_DIRECTORY|O_NOFOLLOW` on each component, then creates output relative to the pinned parent. Unlike RC8, a symlink at an intermediate ancestor is rejected. Changes to privileged mounts or deliberate rename of the pinned directory itself are not confinement guarantees, and the non-Linux fallback is not race-safe. Existing authorized ordinary nested directories still work; symlinked ancestors are intentionally rejected. No evidence-contract changes.
