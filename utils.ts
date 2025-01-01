/**
 * utils.ts
 *
 * Shared utility functions for the jolt-zktls project.
 */

// ─── PKCS8 Key Helpers ────────────────────────────────────────────

/** PKCS8 DER prefix for X25519 (used when wrapping raw keys).
 *  Verified via Node.js crypto.subtle round-trip on 2026-06-14.
 */
export const PKCS8_PREFIXES: Record<string, Uint8Array> = {
    'X25519': new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]),
}

/**
 * Wrap raw private key bytes in a PKCS8 DER structure.
 *
 * Inverse of `stripPkcs8Prefix` — used when re-importing keys
 * from the JSON test vectors via `crypto.subtle.importKey`.
 */
export function wrapPkcs8(raw: Uint8Array, alg: string): Uint8Array {
    const prefix = PKCS8_PREFIXES[alg]
    if (!prefix) throw new Error(`No PKCS8 prefix for ${alg}`)
    const result = new Uint8Array(prefix.length + raw.length)
    result.set(prefix)
    result.set(raw, prefix.length)
    return result
}

/**
 * Strip a PKCS8 DER prefix to extract the raw X25519 private key bytes.
 * The key is always the 32-byte value following the OCTET STRING tag (0x04, 0x20).
 */
export function stripPkcs8Prefix(pkcs8: Uint8Array): Uint8Array {
    for (let i = 0; i < pkcs8.length - 2; i++) {
        if (pkcs8[i] === 0x04 && pkcs8[i + 1] === 0x20) {
            return pkcs8.slice(i + 2, i + 2 + 32)
        }
    }
    // Fallback: skip the 16-byte X25519 prefix
    return pkcs8.slice(16, 48)
}
