/**
 * generate-test-cases.ts
 *
 * Connects to a TLS server, captures all session data, and saves it to
 * test_cases.json — a cross-language test vector for both TS and Rust.
 *
 * Uses the dedicated `recordTLSSession()` function from record/record.ts.
 *
 * Usage:  npx tsx test/generate-test-cases.ts [hostname] [port]
 */

import * as fs from 'node:fs'
import * as path from 'node:path'
import { recordTLSSession } from '../record/record.js'

const HOST = process.argv[2] || 'example.com'
const PORT = parseInt(process.argv[3] || '443', 10)

async function main() {
    console.log(`  🔗 Recording TLS session with ${HOST}:${PORT}…`)

    const session = await recordTLSSession({ host: HOST, port: PORT })

    const outPath = path.resolve(__dirname, './test_cases.json')
    fs.writeFileSync(outPath, JSON.stringify(session, null, 2))

    console.log(`\n  ✅ Session saved to ${outPath}`)
    console.log(`     Name   : ${session.name}`)
    console.log(`     Records: ${session.records.length}`)
    console.log(`     Handshake msgs: ${session.params.handshakeMsgs.length}`)
    console.log(`     Cipher : ${session.params.negotiatedCipherSuite}`)

    for (let i = 0; i < session.records.length; i++) {
        const r = session.records[i]
        const pt = r.expected.plaintextHex
        if (pt) {
            console.log(`     Record ${i} (${r.direction}): ${r.expected.algorithm} → ${pt.slice(0, 32)}…`)
        } else {
            console.log(`     Record ${i} (${r.direction}): ⚠️  decryption failed`)
        }
    }
}

main().catch((err) => {
    console.error(`  ❌ ${err.message}`)
    process.exit(1)
})
