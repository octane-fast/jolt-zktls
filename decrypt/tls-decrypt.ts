/**
 * tls-decrypt.ts
 *
 * TLS 1.3 AEAD decryption — pure functions, no side effects.
 *
 * Provides:
 *   - `decryptRecord`    — AEAD-decrypt a single TLS record
 *   - `deriveKeysFromHandshake` — derive traffic keys from handshake transcript
 *
 * ## Usage
 *
 *   import { decryptRecord } from './decrypt/tls-decrypt.js'
 */

import { createDecipheriv } from 'node:crypto'
import {
    setCryptoImplementation,
    parseServerHello,
    computeSharedKeys,
} from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'

// Register the default Web Crypto implementation for HKDF/key derivation
setCryptoImplementation(webcryptoCrypto as any)

import type { RawRecord, KeyDerivationParams } from '../types.js'
export type { RawRecord, KeyDerivationParams }

export { decryptRecord, deriveKeysFromHandshake }

// ─── TLS 1.3 AEAD Decryption ─────────────────────────────────────

/**
 * TLS 1.3 AEAD decryption.
 *
 * Record format:  AEAD-Encrypt(key, nonce, plaintext || content_type, AAD)
 *   nonce         = fixed_iv ⊕ seq_num  (big-endian, 12 bytes)
 *   AAD           = TLS record header   (type=0x17, ver=0x0303, length)
 *   auth tag      = last 16 bytes of ciphertext
 *   inner content = encrypted(plaintext || real_content_type)
 */
async function decryptRecord(
    rec: RawRecord,
    params: KeyDerivationParams,
): Promise<{
    plaintext: Uint8Array
    algorithm: string
    nonce: Uint8Array
    aad: Uint8Array
} | null> {
    const derived = await deriveKeysFromHandshake(params)
    if (!derived) return null

    const encKey = rec.direction === 'S→C' ? derived.serverEncKey : derived.clientEncKey
    const fixedIv = rec.direction === 'S→C' ? derived.serverIv : derived.clientIv

    // 1. Derive nonce = fixed_iv XOR record_sequence_number
    const nonce = new Uint8Array(12)
    nonce.set(fixedIv)
    const rn = rec.recordNumber
    nonce[11] ^= (rn & 0xFF)
    nonce[10] ^= ((rn >>> 8) & 0xFF)
    nonce[9]  ^= ((rn >>> 16) & 0xFF)
    nonce[8]  ^= ((rn >>> 24) & 0xFF)

    // 2. Construct AAD = TLS 1.3 record header
    const ctLen = rec.ciphertext.length
    const aad = new Uint8Array([0x17, 0x03, 0x03, (ctLen >> 8) & 0xFF, ctLen & 0xFF])

    // 3. Split ciphertext → encrypted_data + auth_tag (last 16 bytes)
    const authTag = rec.ciphertext.slice(-16)
    const encData = rec.ciphertext.slice(0, -16)

    // 4. Try decryption algorithms based on key length
    const candidates: [string, number][] = encKey.length === 32
        ? [['chacha20-poly1305', 32], ['aes-256-gcm', 32]]
        : encKey.length === 16
            ? [['aes-128-gcm', 16]]
            : []

    for (const [algo] of candidates) {
        try {
            const decipher = createDecipheriv(algo as any, encKey, nonce)
            decipher.setAAD(aad)
            decipher.setAuthTag(authTag)
            const dec = Buffer.concat([decipher.update(encData), decipher.final()])

            // TLS 1.3: last byte is the real content type, hidden inside the encryption
            const plaintext = new Uint8Array(dec.slice(0, -1))
            return { plaintext, algorithm: algo, nonce, aad }
        } catch {
            // Wrong algorithm — try next
        }
    }
    return null
}

// ─── Key Derivation from Handshake ────────────────────────────────

/**
 * Derives TLS 1.3 traffic keys from scratch:
 *   ECDH shared_secret → HKDF(handshake_transcript) → traffic_keys
 */
async function deriveKeysFromHandshake(params: KeyDerivationParams): Promise<{
    serverEncKey: Uint8Array; serverIv: Uint8Array
    clientEncKey: Uint8Array; clientIv: Uint8Array
} | null> {
    const { capturedPrivKeys, negotiatedCipherSuite, handshakeMsgs } = params
    if (Object.keys(capturedPrivKeys).length === 0 || !negotiatedCipherSuite || handshakeMsgs.length < 2) {
        return null
    }

    try {
        const serverHello = await parseServerHello(handshakeMsgs[1].slice(4))
        if (!serverHello.publicKey || !serverHello.publicKeyType) {
            throw new Error('ServerHello has no key share')
        }

        const privKeyForCurve = capturedPrivKeys[serverHello.publicKeyType]
        if (!privKeyForCurve) {
            throw new Error(`No captured private key for ${serverHello.publicKeyType}`)
        }
        const sharedSecret = await webcryptoCrypto.calculateSharedSecret(
            serverHello.publicKeyType as any,
            privKeyForCurve as any,
            serverHello.publicKey as any,
        )

        const hsKeys = await computeSharedKeys({
            masterSecret: new Uint8Array(sharedSecret),
            cipherSuite: negotiatedCipherSuite as any,
            hellos: handshakeMsgs.slice(0, 2),
            secretType: 'hs',
        })

        const apKeys = await computeSharedKeys({
            masterSecret: hsKeys.masterSecret,
            cipherSuite: negotiatedCipherSuite as any,
            hellos: handshakeMsgs,
            secretType: 'ap',
        })

        return {
            serverEncKey: apKeys.serverEncKey instanceof Uint8Array
                ? new Uint8Array(apKeys.serverEncKey) : new Uint8Array(0),
            serverIv: new Uint8Array(apKeys.serverIv),
            clientEncKey: apKeys.clientEncKey instanceof Uint8Array
                ? new Uint8Array(apKeys.clientEncKey) : new Uint8Array(0),
            clientIv: new Uint8Array(apKeys.clientIv),
        }
    } catch {
        return null
    }
}
