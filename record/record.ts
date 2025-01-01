/**
 * record.ts
 *
 * Dedicated TLS session recorder. Connects to a TLS server, captures the
 * full handshake transcript + encrypted records, derives traffic keys,
 * and produces a TLSSession object matching the test_cases.json schema.
 *
 * ## Usage
 *
 *   import { recordTLSSession } from './record.js'
 *
 *   const session = await recordTLSSession({ host: 'example.com' })
 *   console.log(session.name)          // "example.com TLS_CHACHA20_POLY1305_SHA256"
 *   console.log(session.records.length) // number of captured records
 */

import { Socket } from 'node:net'
import {
    makeTLSClient,
    setCryptoImplementation,
} from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'
import type { TLSPacketContext } from '@reclaimprotocol/tls'
import { decryptRecord as tlsDecryptRecord } from '../decrypt/tls-decrypt.js'
import type {
    RawRecord,
    KeyDerivationParams,
    RecordExpected,
    TLSSessionRecord,
    TLSSessionParams,
    TLSSession,
    RecordOptions,
} from '../types.js'
import { stripPkcs8Prefix } from '../utils.js'
export type { RecordExpected, TLSSessionRecord, TLSSessionParams, TLSSession, RecordOptions }

// ─── Internal Types ───────────────────────────────────────────────

interface CapturedRecord {
    ciphertextHex: string
    recordNumber: number
    direction: 'S→C' | 'C→S'
}



// ─── Main Recording Function ──────────────────────────────────────

/**
 * Connects to a TLS server, performs a handshake, sends an HTTP request,
 * captures all encrypted records, and returns a TLSSession object that
 * matches the test_cases.json schema.
 */
export function recordTLSSession(options: RecordOptions): Promise<TLSSession> {
    const host = options.host
    const port = options.port ?? 443
    const timeout = options.timeout ?? 15_000

    return new Promise<TLSSession>((resolve, reject) => {
        // ── Captured state (local to this recording) ──
        const capturedPrivKeysHex: Record<string, string> = {}
        const capturedPrivKeysCrypto: Record<string, unknown> = {}
        const handshakeMsgsHex: string[] = []
        const capturedRecords: CapturedRecord[] = []
        let negotiatedCipherSuite = ''
        let clientEncKeyLen = 0
        let clientSendSeq = 0
        let settled = false

        const timer = setTimeout(() => {
            if (!settled) {
                settled = true
                socket.destroy()
                reject(new Error(`Connection to ${host}:${port} timed out after ${timeout}ms`))
            }
        }, timeout)

        function done(session: TLSSession) {
            if (settled) return
            settled = true
            clearTimeout(timer)
            resolve(session)
        }

        function fail(err: Error) {
            if (settled) return
            settled = true
            clearTimeout(timer)
            reject(err)
        }

        // ── Wrapped crypto: captures private keys as raw hex ──
        const wrappedCrypto = {
            ...webcryptoCrypto,
            async generateKeyPair(alg: string) {
                const kp = await webcryptoCrypto.generateKeyPair(alg as any)
                if (alg === 'X25519') {
                    try {
                        const pkcs8 = await crypto.subtle.exportKey('pkcs8', kp.privKey as any)
                        const raw = stripPkcs8Prefix(new Uint8Array(pkcs8))
                        capturedPrivKeysHex[alg] = Buffer.from(raw).toString('hex')
                    } catch {
                        // Key export not supported for this curve
                    }
                    capturedPrivKeysCrypto[alg] = kp.privKey
                }
                return kp
            },
        }

        setCryptoImplementation(wrappedCrypto as any)

        // ── TLS Client ──
        const socket = new Socket()

        const tls = makeTLSClient({
            host,
            verifyServerCertificate: true,
            namedCurves: ['X25519'],
            logger: {
                debug: () => {},
                info: () => {},
                warn: () => {},
                error: console.error,
                trace: () => {},
            },

            async write({ header, content }) {
                socket.write(header)
                socket.write(content)

                // Capture outbound handshake messages
                if (header[0] === 0x16) {
                    handshakeMsgsHex.push(Buffer.from(content).toString('hex'))
                }

                // Capture outbound encrypted records after handshake
                if (header[0] === 0x17 && clientEncKeyLen > 0) {
                    capturedRecords.push({
                        ciphertextHex: Buffer.from(content).toString('hex'),
                        recordNumber: clientSendSeq++,
                        direction: 'C→S',
                    })
                }
            },

            onHandshake() {
                const meta = tls.getMetadata()
                negotiatedCipherSuite = meta.cipherSuite || ''

                const keys = tls.getKeys()
                if (keys) {
                    clientEncKeyLen = keys.clientEncKey instanceof Uint8Array
                        ? keys.clientEncKey.length
                        : 0
                }

                // Build HTTP request with Host and any custom headers
                const reqPath = options.path || '/'
                let request = `GET ${reqPath} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n`
                if (options.headers) {
                    process.stderr.write(JSON.stringify({ status: 'debug', step: `Applying ${Object.keys(options.headers).length} custom headers` }) + '\n')
                    for (const [key, value] of Object.entries(options.headers)) {
                        if (key.toLowerCase() !== 'host') { // Host is already set
                            request += `${key}: ${value}\r\n`
                        }
                    }
                }
                request += `\r\n`
                tls.write(new TextEncoder().encode(request))
            },

            onApplicationData() {},

            onRead(_packet: any, ctx: TLSPacketContext) {
                // Capture handshake messages during handshake phase
                if (clientEncKeyLen === 0) {
                    if (ctx.type === 'ciphertext' && ctx.contentType === 'HANDSHAKE') {
                        handshakeMsgsHex.push(Buffer.from(_packet.content).toString('hex'))
                    } else if (ctx.type === 'plaintext' && _packet.header?.[0] === 0x16) {
                        handshakeMsgsHex.push(Buffer.from(_packet.content).toString('hex'))
                    }
                }

                // Capture inbound encrypted records
                if (ctx.type === 'ciphertext' && ctx.contentType === 'APPLICATION_DATA') {
                    capturedRecords.push({
                        ciphertextHex: Buffer.from(ctx.ciphertext).toString('hex'),
                        recordNumber: ctx.recordNumber,
                        direction: 'S→C',
                    })
                }
            },

            onRecvCertificates() {},

            async onTlsEnd(error) {
                if (error && error.message !== 'CLOSE_NOTIFY') {
                    socket.destroy()
                    fail(new Error(`TLS error: ${error.message}`))
                    return
                }

                try {
                    const session = await buildSession()
                    socket.destroy()
                    done(session)
                } catch (err: any) {
                    socket.destroy()
                    fail(err)
                }
            },
        })

        // ── Build the TLSSession from captured state ──
        async function buildSession(): Promise<TLSSession> {
            const handshakeMsgs = handshakeMsgsHex.map(h => Buffer.from(h, 'hex'))
            const params: KeyDerivationParams = {
                capturedPrivKeys: capturedPrivKeysCrypto,
                negotiatedCipherSuite,
                handshakeMsgs,
            }

            const records: TLSSessionRecord[] = []
            for (const rec of capturedRecords) {
                let expected: RecordExpected = {
                    plaintextHex: '',
                    algorithm: '',
                    nonceHex: '',
                    aadHex: '',
                }

                const rawRec: RawRecord = {
                    ciphertext: Buffer.from(rec.ciphertextHex, 'hex'),
                    recordNumber: rec.recordNumber,
                    direction: rec.direction,
                }
                const result = await tlsDecryptRecord(rawRec, params)
                if (result) {
                    expected = {
                        plaintextHex: Buffer.from(result.plaintext).toString('hex'),
                        algorithm: result.algorithm,
                        nonceHex: Buffer.from(result.nonce).toString('hex'),
                        aadHex: Buffer.from(result.aad).toString('hex'),
                    }
                }

                records.push({
                    ciphertext: rec.ciphertextHex,
                    recordNumber: rec.recordNumber,
                    direction: rec.direction === 'S→C' ? 'ServerToClient' : 'ClientToServer',
                    expected,
                })
            }

            return {
                name: `${host} ${negotiatedCipherSuite}`,
                params: {
                    capturedPrivKeys: capturedPrivKeysHex,
                    negotiatedCipherSuite,
                    handshakeMsgs: handshakeMsgsHex,
                },
                records,
            }
        }

        // ── Connect ──
        socket.connect(port, host, () => tls.startHandshake())

        socket.on('data', (data) => {
            tls.handleReceivedBytes(new Uint8Array(data.buffer, data.byteOffset, data.byteLength))
        })

        socket.on('error', (err) => {
            fail(new Error(`Socket error: ${err.message}`))
        })
    })
}
