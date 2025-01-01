/**
 * types.ts
 *
 * Shared TypeScript types for the jolt-zktls project.
 */

// ─── Record / Session Types ───────────────────────────────────────

/** Expected decryption output for a single record. */
export interface RecordExpected {
    plaintextHex: string
    algorithm: string
    nonceHex: string
    aadHex: string
}

/** A single captured TLS record with its expected decryption result. */
export interface TLSSessionRecord {
    ciphertext: string
    recordNumber: number
    direction: 'ServerToClient' | 'ClientToServer'
    expected: RecordExpected
}

/** The session parameters needed for key derivation. */
export interface TLSSessionParams {
    capturedPrivKeys: Record<string, string>
    negotiatedCipherSuite: string
    handshakeMsgs: string[]
}

/** A complete TLS session capture — matches test_cases.json schema. */
export interface TLSSession {
    name: string
    params: TLSSessionParams
    records: TLSSessionRecord[]
}

/** Options for the recording function. */
export interface RecordOptions {
    /** Target hostname (e.g. 'example.com') */
    host: string
    /** Target port (default: 443) */
    port?: number
    /** URL path (default: '/') */
    path?: string
    /** Connection timeout in ms (default: 15000) */
    timeout?: number
    /** Custom HTTP headers to send with the request */
    headers?: Record<string, string>
}

// ─── Decryption Types ─────────────────────────────────────────────

/** A raw TLS record with ciphertext as bytes. */
export interface RawRecord {
    ciphertext: Uint8Array
    recordNumber: number
    direction: 'S→C' | 'C→S'
}

/** Parameters needed to derive TLS 1.3 traffic keys from a handshake. */
export interface KeyDerivationParams {
    capturedPrivKeys: Record<string, unknown>
    negotiatedCipherSuite: string
    handshakeMsgs: Uint8Array[]
}
