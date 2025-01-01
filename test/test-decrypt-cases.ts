/**
 * test-decrypt-cases.ts
 *
 * Reads test_cases.json and verifies decryptRecord() produces the expected outputs.
 *
 * Usage:  npx tsx test/test-decrypt-cases.ts
 */

import { decryptRecord } from '../decrypt/tls-decrypt.js'
import * as fs from 'node:fs'
import * as path from 'node:path'
import type { TLSSession, TLSSessionParams } from '../types.js'
import { wrapPkcs8, PKCS8_PREFIXES } from '../utils.js'

const testCasesPath = path.resolve(__dirname, './test_cases.json')

if (!fs.existsSync(testCasesPath)) {
    console.error(`  ❌ ${testCasesPath} not found. Run generate-test-cases.ts first.`)
    process.exit(1)
}

const tc: TLSSession = JSON.parse(fs.readFileSync(testCasesPath, 'utf8'))

console.log(`  🧪 Testing: ${tc.name}`)
console.log(`  Cipher: ${tc.params.negotiatedCipherSuite}`)
console.log(`  Handshake msgs: ${tc.params.handshakeMsgs.length}`)
console.log(`  Records: ${tc.records.length}\n`)

// Rehydrate params: import private keys as CryptoKey via PKCS8 wrapping
async function buildParams(raw: TLSSessionParams) {
    const capturedPrivKeys: Record<string, unknown> = {}
    for (const [alg, hex] of Object.entries(raw.capturedPrivKeys) as [string, string][]) {
        // Only import keys we can re-wrap in PKCS8 (currently X25519)
        if (!(alg in PKCS8_PREFIXES)) continue
        const rawBytes = Buffer.from(hex, 'hex')
        const pkcs8 = wrapPkcs8(rawBytes, alg)
        const imported = await crypto.subtle.importKey(
            'pkcs8', pkcs8,
            alg === 'X25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve: alg },
            true, ['deriveBits'],
        )
        capturedPrivKeys[alg] = imported
    }

    return {
        capturedPrivKeys,
        negotiatedCipherSuite: raw.negotiatedCipherSuite,
        handshakeMsgs: raw.handshakeMsgs.map((h: string) => Buffer.from(h, 'hex')),
    }
}

async function main() {
    const params = await buildParams(tc.params)
    let passed = 0
    let failed = 0

    for (let i = 0; i < tc.records.length; i++) {
        const r = tc.records[i]
        const rec = {
            ciphertext: Buffer.from(r.ciphertext, 'hex'),
            recordNumber: r.recordNumber,
            direction: r.direction === 'ServerToClient' ? 'S→C' as const : 'C→S' as const,
        }

        const result = await decryptRecord(rec, params)
        const exp = r.expected

        if (!result) {
            console.error(`  ❌ Record ${i}: decryptRecord returned null`)
            failed++
            continue
        }

        const ptMatch = Buffer.from(result.plaintext).toString('hex') === exp.plaintextHex
        const algoMatch = result.algorithm === exp.algorithm
        const nonceMatch = Buffer.from(result.nonce).toString('hex') === exp.nonceHex

        if (ptMatch && algoMatch && nonceMatch) {
            console.log(`  ✅ Record ${i} (${r.direction}): ${result.algorithm} — ${exp.plaintextHex.slice(0, 32)}…`)
            passed++
        } else {
            console.error(`  ❌ Record ${i} (${r.direction}): MISMATCH`)
            if (!ptMatch) console.error(`     plaintext: got ${Buffer.from(result.plaintext).toString('hex').slice(0, 32)}… expected ${exp.plaintextHex.slice(0, 32)}…`)
            if (!algoMatch) console.error(`     algorithm: got ${result.algorithm} expected ${exp.algorithm}`)
            if (!nonceMatch) console.error(`     nonce: got ${Buffer.from(result.nonce).toString('hex')} expected ${exp.nonceHex}`)
            failed++
        }
    }

    console.log(`\n  ${passed} passed, ${failed} failed`)
    if (failed > 0) process.exit(1)
}

main()
