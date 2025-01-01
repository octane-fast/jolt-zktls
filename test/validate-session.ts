/**
 * validate-session.ts
 *
 * Validates a TLS session JSON file by attempting to decrypt all records.
 * Works with output from both the TS recorder and the C++ recorder.
 *
 * Usage:  npx tsx test/validate-session.ts <session.json>
 *
 * Exit code:
 *   0 = all records decrypted successfully
 *   1 = one or more records failed
 *   2 = input error
 */

import { decryptRecord, deriveKeysFromHandshake } from '../decrypt/tls-decrypt.js'
import { createDecipheriv } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import type { TLSSession, TLSSessionParams } from '../types.js'
import { wrapPkcs8, PKCS8_PREFIXES } from '../utils.js'

const sessionPath = process.argv[2]

if (!sessionPath) {
    console.error('Usage: npx tsx test/validate-session.ts <session.json>')
    process.exit(2)
}

const resolvedPath = path.resolve(sessionPath)
if (!fs.existsSync(resolvedPath)) {
    console.error(`  ❌ File not found: ${resolvedPath}`)
    process.exit(2)
}

const tc: TLSSession = JSON.parse(fs.readFileSync(resolvedPath, 'utf8'))

console.log(`  📂 Session: ${tc.name}`)
console.log(`  Cipher: ${tc.params.negotiatedCipherSuite}`)
console.log(`  Handshake msgs: ${tc.params.handshakeMsgs.length}`)
console.log(`  Records: ${tc.records.length}`)

// Show private key info
for (const [alg, hex] of Object.entries(tc.params.capturedPrivKeys)) {
    console.log(`  Key ${alg}: ${hex.length} hex chars (${hex.length / 2} bytes)`)
}

console.log()

// Rehydrate private keys as CryptoKey objects
async function buildParams(raw: TLSSessionParams) {
    const capturedPrivKeys: Record<string, unknown> = {}
    for (const [alg, hex] of Object.entries(raw.capturedPrivKeys) as [string, string][]) {
        if (!(alg in PKCS8_PREFIXES)) {
            console.warn(`  ⚠️  No PKCS8 prefix for ${alg}, skipping key import`)
            continue
        }
        const rawBytes = Buffer.from(hex, 'hex')
        if (rawBytes.length !== 32) {
            console.warn(`  ⚠️  ${alg} key is ${rawBytes.length} bytes (expected 32), skipping`)
            continue
        }
        const pkcs8 = wrapPkcs8(rawBytes, alg)
        try {
            const imported = await crypto.subtle.importKey(
                'pkcs8', pkcs8,
                alg === 'X25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve: alg },
                true, ['deriveBits'],
            )
            capturedPrivKeys[alg] = imported
            console.log(`  ✅ Imported ${alg} key`)
        } catch (e) {
            console.error(`  ❌ Failed to import ${alg} key: ${(e as Error).message}`)
        }
    }

    return {
        capturedPrivKeys,
        negotiatedCipherSuite: raw.negotiatedCipherSuite,
        handshakeMsgs: raw.handshakeMsgs.map((h: string) => Buffer.from(h, 'hex')),
    }
}

async function main() {
    // Check if traffic keys are provided directly (from C++ recorder keylog)
    const hasTrafficKeys = !!(tc.params as any).serverTrafficKey
    let trafficKeys: {
        serverKey: Buffer; serverIv: Buffer
        clientKey: Buffer; clientIv: Buffer
    } | null = null

    if (hasTrafficKeys) {
        console.log('  🔑 Using keylog-derived traffic keys (direct AEAD)')
        trafficKeys = {
            serverKey: Buffer.from((tc.params as any).serverTrafficKey, 'hex'),
            serverIv: Buffer.from((tc.params as any).serverTrafficIv, 'hex'),
            clientKey: Buffer.from((tc.params as any).clientTrafficKey, 'hex'),
            clientIv: Buffer.from((tc.params as any).clientTrafficIv, 'hex'),
        }
    } else {
        console.log('  🔑 Deriving traffic keys from handshake transcript')
    }

    const params = hasTrafficKeys ? null : await buildParams(tc.params)

    if (!hasTrafficKeys && Object.keys(params!.capturedPrivKeys).length === 0) {
        console.error('  ❌ No valid private keys imported — cannot decrypt')
        process.exit(1)
    }

    let passed = 0
    let failed = 0
    let skipped = 0

    for (let i = 0; i < tc.records.length; i++) {
        const r = tc.records[i]
        const rec = {
            ciphertext: Buffer.from(r.ciphertext, 'hex'),
            recordNumber: r.recordNumber,
            direction: r.direction === 'ServerToClient' ? 'S→C' as const : 'C→S' as const,
        }

        if (rec.ciphertext.length === 0) {
            console.log(`  ⏭️  Record ${i} (${r.direction}): empty ciphertext, skipping`)
            skipped++
            continue
        }

        let plaintext: Buffer | null = null
        let algorithm = ''

        try {
            if (trafficKeys) {
                // Direct AEAD decryption using traffic keys
                const key = rec.direction === 'S→C' ? trafficKeys.serverKey : trafficKeys.clientKey
                const fixedIv = rec.direction === 'S→C' ? trafficKeys.serverIv : trafficKeys.clientIv
                const nonce = Buffer.from(fixedIv)
                const rn = rec.recordNumber
                nonce[11] ^= (rn & 0xff)
                nonce[10] ^= ((rn >>> 8) & 0xff)
                nonce[9]  ^= ((rn >>> 16) & 0xff)
                nonce[8]  ^= ((rn >>> 24) & 0xff)

                const ct = rec.ciphertext
                const aad = Buffer.from([0x17, 0x03, 0x03, (ct.length >> 8) & 0xff, ct.length & 0xff])
                const authTag = ct.slice(-16)
                const encData = ct.slice(0, -16)

                // Try ChaCha20-Poly1305 first, then AES-GCM
                for (const [algo, fn] of [
                    ['chacha20-poly1305', () => {
                        const d = createDecipheriv('chacha20-poly1305', key, nonce)
                        d.setAAD(aad); d.setAuthTag(authTag)
                        return Buffer.concat([d.update(encData), d.final()])
                    }],
                    ['aes-256-gcm', () => {
                        const d = createDecipheriv('aes-256-gcm', key, nonce)
                        d.setAAD(aad); d.setAuthTag(authTag)
                        return Buffer.concat([d.update(encData), d.final()])
                    }],
                    ['aes-128-gcm', () => {
                        const d = createDecipheriv('aes-128-gcm', key, nonce)
                        d.setAAD(aad); d.setAuthTag(authTag)
                        return Buffer.concat([d.update(encData), d.final()])
                    }],
                ] as [string, () => Buffer][]) {
                    try {
                        const dec = fn()
                        // TLS 1.3: last byte is the real content type
                        plaintext = dec.slice(0, -1)
                        algorithm = algo
                        break
                    } catch { /* wrong algo, try next */ }
                }
            } else {
                // Use the decryptRecord function (derives keys from handshake)
                const result = await decryptRecord(rec, params!)
                if (result) {
                    plaintext = Buffer.from(result.plaintext)
                    algorithm = result.algorithm
                }
            }

            if (!plaintext) {
                console.error(`  ❌ Record ${i} (${r.direction}): decryption failed`)
                failed++
                continue
            }

            const ptHex = plaintext.toString('hex')
            const ptAscii = plaintext.toString('ascii')
                .replace(/[^\x20-\x7e]/g, '·')

            if (r.expected.plaintextHex) {
                if (ptHex === r.expected.plaintextHex) {
                    console.log(`  ✅ Record ${i} (${r.direction}): ${algorithm} — ${ptHex.slice(0, 40)}…`)
                } else {
                    console.error(`  ❌ Record ${i} (${r.direction}): plaintext mismatch`)
                    failed++
                    continue
                }
            } else {
                console.log(`  ✅ Record ${i} (${r.direction}): ${algorithm} — ${ptAscii.slice(0, 60)}`)
            }

            passed++
        } catch (e) {
            console.error(`  ❌ Record ${i} (${r.direction}): ${(e as Error).message}`)
            failed++
        }
    }

    console.log(`\n  Results: ${passed} passed, ${failed} failed, ${skipped} skipped`)

    if (failed > 0) {
        process.exit(1)
    }
}

main().catch((e) => {
    console.error(`  ❌ Fatal: ${e.message}`)
    process.exit(1)
})
