> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# AuthMatrix v0.1.0-rc10 release candidate — 2026-10-14

Prior Linux output-directory fix (RC8/RC9). Reproduced RC7: 48 writes outside intended pinned real directory in 450 synthetic CLI attempts; RC8: zero outside writes in same synthetic harness, with 450 attempts. This does not claim security against malicious ancestor swaps, mount remapping, compromised filesystem owners or any native Windows/macOS runtime. Strict verifier, schema and result contract unchanged.

Status: Linux AMD64 candidate under qualification, **NOT a stable v1**. Supported Go toolchain, staticcheck, govulncheck, native macOS/Windows tests, repository/module ownership and publisher provenance remain release gates.

## 2026-10-14 — RC9 Linux ancestor hardening
Linux now pins path traversal from `/` using `openat` with `O_PATH|O_DIRECTORY|O_NOFOLLOW` on each component, then creates output relative to the pinned parent. Unlike RC8, a symlink at an intermediate ancestor is rejected. Changes to privileged mounts or deliberate rename of the pinned directory itself are not confinement guarantees, and the non-Linux fallback is not race-safe. Existing authorized ordinary nested directories still work; symlinked ancestors are intentionally rejected. No evidence-contract changes.

## 2026-10-14 — RC10 source ZIP structural verification
Corrects pre-extraction archive portability checks for colliding intermediate
path components and file/directory contradictions. A ZIP with matching SHA-256
values is not necessarily safe or portable to extract. See regression cases
16–18 in tools/test_verify_source_archive.py. Runtime evaluation and versioned
JSON evidence contract are unchanged. Linux Go1.23.2 tests are lab-only; this
release candidate remains blocked from stable v1 status.


### Audit 193 qualification revision to RC10 source (no product-code or schema change)

No newly confirmed product defect. Previous CI omitted native Linux ARM64 and restricted existing macOS/Windows jobs to manual/tag-only events. Native jobs now execute for PRs and pushes, verify pinned Go 1.27.2, run Go race/vet/build/mod verify, and run a portable positive/negative/sensitive-output smoke. Old workflow is confirmed RED under the new static regression; updated workflow GREEN. **GitHub Actions has not executed:** platform runtime and supported Go/analyzers remain blocked.
