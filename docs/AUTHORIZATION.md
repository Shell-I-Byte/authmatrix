> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Scope and authorization

Operate only on your own synthetic fixtures or explicitly authorized material. The input `authorization` object is an explicit declaration by the operator: `approved=true`, `origin=synthetic|explicitly-authorized`, `scope=<bounded opaque identifier>`. The CLI makes **zero** outgoing network requests. If approval is absent or false, it refuses to evaluate.

Never insert passwords, session tokens or personally identifiable data in the file. Scope identifiers should be opaque non-sensitive labels. Evidence contains SHA-256 digests, not plaintext IDs. Approval is not independently verified.
