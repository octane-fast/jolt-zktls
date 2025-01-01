#!/usr/bin/env npx tsx
/**
 * prove-url.ts
 *
 * CLI tool that records a TLS 1.3 session and proves its decryption using
 * the Jolt zkVM. Designed to be spawned by the Octane Accelerator.
 *
 * Usage:
 *   npx tsx cli/prove-url.ts --url https://example.com [--headers '{"Accept":"text/html"}']
 *
 * Stderr: status updates as JSON lines:  {"status":"recording","step":"Connecting..."}
 * Stdout: final result as JSON:          {"ok":true,"records":3,"plaintext":["hex1","hex2"]}
 *
 * Exit codes:
 *   0 = success
 *   1 = recording error
 *   2 = proving error
 */

import * as path from 'node:path'
import * as fs from 'node:fs'
import * as os from 'node:os'
import { execFileSync } from 'node:child_process'
import { recordTLSSession } from '../record/record.js'

// ─── CLI Argument Parsing ─────────────────────────────────────────

function parseArgs(argv: string[]): { url: string; headers: Record<string, string>; records?: number[] } {
    let url = ''
    let headersJson = '{}'
    let recordsJson = ''

    for (let i = 2; i < argv.length; i++) {
        if (argv[i] === '--url' && argv[i + 1]) {
            url = argv[++i]
        } else if (argv[i] === '--headers' && argv[i + 1]) {
            headersJson = argv[++i]
        } else if (argv[i] === '--records' && argv[i + 1]) {
            recordsJson = argv[++i]
        }
    }

    if (!url) {
        process.stderr.write(JSON.stringify({ error: 'Missing --url argument' }) + '\n')
        process.exit(1)
    }

    // Parse URL to extract host and port
    let parsed: URL
    try {
        parsed = new URL(url)
    } catch {
        process.stderr.write(JSON.stringify({ error: `Invalid URL: ${url}` }) + '\n')
        process.exit(1)
    }

    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
        process.stderr.write(JSON.stringify({ error: 'URL must use https: or http:' }) + '\n')
        process.exit(1)
    }

    let headers: Record<string, string> = {}
    try {
        headers = JSON.parse(headersJson)
    } catch {
        process.stderr.write(JSON.stringify({ error: 'Invalid --headers JSON' }) + '\n')
        process.exit(1)
    }

    let records: number[] | undefined
    if (recordsJson) {
        try {
            const parsed = JSON.parse(recordsJson)
            if (Array.isArray(parsed)) records = parsed.filter((n: any) => typeof n === 'number')
        } catch {
            // Try comma-separated format
            records = recordsJson.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n))
        }
    }

    return { url, headers, records }
}

function status(step: string) {
    process.stderr.write(JSON.stringify({ status: 'running', step }) + '\n')
}

// ─── Main ─────────────────────────────────────────────────────────

async function main() {
    const { url, headers, records } = parseArgs(process.argv)
    const parsed = new URL(url)
    const host = parsed.hostname
    const port = parsed.port ? parseInt(parsed.port, 10) : 443
    const urlPath = parsed.pathname + parsed.search

    // ── Step 1: Record TLS session ──
    status(`Recording TLS session with ${host}:${port}${urlPath}...`)

    let session
    try {
        session = await recordTLSSession({ host, port, path: urlPath, headers })
    } catch (err: any) {
        process.stderr.write(JSON.stringify({ error: `TLS recording failed: ${err.message}` }) + '\n')
        process.exit(1)
    }

    status(`Captured ${session.records.length} records (${session.params.negotiatedCipherSuite})`)

    // Filter to requested record indices if specified
    if (records && records.length > 0) {
        const maxIdx = session.records.length - 1
        const valid = records.filter(i => i >= 0 && i <= maxIdx)
        if (valid.length === 0) {
            process.stderr.write(JSON.stringify({ error: `No valid record indices (have ${session.records.length} records)` }) + '\n')
            process.exit(1)
        }
        session.records = valid.map(i => session.records[i])
        status(`Filtered to ${session.records.length} records (indices: ${valid.join(',')})`)
    }

    // ── Step 2: Write session to temp file ──
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jolt-zktls-'))
    const sessionPath = path.join(tmpDir, 'session.json')
    const outputPath = path.join(tmpDir, 'output.json')

    fs.writeFileSync(sessionPath, JSON.stringify(session, null, 2))
    status(`Session data written to ${sessionPath}`)

    // ── Step 3: Run Jolt prover ──
    // Find the jolt_prove binary (check common locations)
    const projectRoot = path.resolve(import.meta.dirname ?? __dirname, '..')
    const isWindows = process.platform === 'win32'
    const exeSuffix = isWindows ? '.exe' : ''
    const pathSep = isWindows ? ';' : ':'
    const binaryCandidates = [
        // Embedded binary (extracted from Accelerator bundle)
        path.join(projectRoot, `prove/target/release/jolt_prove${exeSuffix}`),
        path.join(projectRoot, `prove/target/debug/jolt_prove${exeSuffix}`),
        // Also check the original source tree (when running from extracted bundle)
        path.resolve(projectRoot, `../../jolt-zktls/prove/target/release/jolt_prove${exeSuffix}`),
        path.resolve(projectRoot, `../../jolt-zktls/prove/target/debug/jolt_prove${exeSuffix}`),
        // Check home directory common locations
        path.join(os.homedir(), `jolt-zktls/prove/target/release/jolt_prove${exeSuffix}`),
        path.join(os.homedir(), `jolt-zktls/prove/target/debug/jolt_prove${exeSuffix}`),
        // Check PATH directories
        ...((process.env.PATH ?? '').split(pathSep).map(p => path.join(p, `jolt_prove${exeSuffix}`))),
    ]

    let binaryPath = ''
    for (const candidate of binaryCandidates) {
        if (fs.existsSync(candidate)) {
            binaryPath = candidate
            break
        }
    }

    if (!binaryPath) {
        // Try to build it — ensure cargo is in PATH
        const cargoPath = path.join(os.homedir(), '.cargo', 'bin')
        const env = { ...process.env }
        if (!env.PATH?.includes(cargoPath)) {
            env.PATH = cargoPath + ':' + (env.PATH ?? '')
        }
        status('Building jolt_prove binary...')
        try {
            // Try multiple prove directories
            const proveDirs = [
                path.join(projectRoot, 'prove'),
                path.resolve(projectRoot, '../../jolt-zktls/prove'),
                path.join(os.homedir(), 'jolt-zktls/prove'),
            ]
            let built = false
            for (const proveDir of proveDirs) {
                if (fs.existsSync(path.join(proveDir, 'Cargo.toml'))) {
                    try {
                        execFileSync('cargo', ['build', '--bin', 'jolt_prove'], {
                            cwd: proveDir,
                            env,
                            stdio: ['pipe', 'pipe', 'pipe'],
                            timeout: 300_000,
                        })
                        binaryPath = path.join(proveDir, 'target/debug/jolt_prove')
                        built = true
                        break
                    } catch { /* try next */ }
                }
            }
            if (!built) throw new Error('No Cargo.toml found in any prove directory')
        } catch (err: any) {
            process.stderr.write(JSON.stringify({
                error: `Failed to build jolt_prove: ${err.stderr?.toString() ?? err.message}`
            }) + '\n')
            process.exit(2)
        }
    }

    status(`Running Jolt prover (${path.basename(binaryPath)})...`)

    // The prove binary needs to run from its prove/ directory so Jolt can
    // find the workspace root (Cargo.toml with [workspace]) and compile
    // the guest program at runtime.
    const proveDir = path.resolve(binaryPath, '../../..') // target/release/jolt_prove → prove/
    const cargoPath = path.join(os.homedir(), '.cargo', 'bin')
    const proverEnv = { ...process.env }
    if (!proverEnv.PATH?.includes(cargoPath)) {
        proverEnv.PATH = cargoPath + ':' + (proverEnv.PATH ?? '')
    }
    // Limit rayon threads to avoid EWOULDBLOCK from nested thread pools
    // (arkworks scalar_mul creates rayon pools inside rayon workers).
    // Also increase thread stack size to 64MB to prevent stack overflow.
    const cores = os.cpus().length
    proverEnv.RAYON_NUM_THREADS = proverEnv.RAYON_NUM_THREADS ?? String(Math.max(1, Math.floor(cores / 2)))
    proverEnv.RUST_MIN_STACK = proverEnv.RUST_MIN_STACK ?? String(64 * 1024 * 1024)

    let proverOutput: string
    try {
        proverOutput = execFileSync(binaryPath, [sessionPath, outputPath], {
            cwd: proveDir,
            env: proverEnv,
            encoding: 'utf-8',
            timeout: 600_000, // 10 min — proving can be slow
            maxBuffer: 10 * 1024 * 1024, // 10MB
            stdio: ['pipe', 'pipe', 'inherit'], // inherit stderr so timing messages pass through
        })
    } catch (err: any) {
        const stderr = err.stderr?.toString() ?? ''
        // Forward any status lines from the prover
        for (const line of stderr.split('\n')) {
            if (line.trim()) {
                try {
                    const msg = JSON.parse(line)
                    if (msg.status === 'running') status(msg.step)
                } catch { /* ignore non-JSON lines */ }
            }
        }
        process.stderr.write(JSON.stringify({ error: `Jolt prover failed: ${err.message}` }) + '\n')
        process.exit(2)
    }

    // ── Step 4: Read and output results ──
    let results: any
    try {
        results = JSON.parse(fs.readFileSync(outputPath, 'utf-8'))
    } catch {
        // Fallback: parse from stdout
        try {
            results = JSON.parse(proverOutput)
        } catch {
            process.stderr.write(JSON.stringify({ error: 'Failed to parse prover output' }) + '\n')
            process.exit(2)
        }
    }

    if (!results.ok) {
        process.stderr.write(JSON.stringify({ error: results.error ?? 'Proving failed' }) + '\n')
        process.exit(2)
    }

    // Output final result on stdout
    const output = {
        ok: true,
        name: session.name,
        cipherSuite: session.params.negotiatedCipherSuite,
        records: results.records,
    }

    process.stdout.write(JSON.stringify(output) + '\n')

    // Cleanup temp files
    try { fs.unlinkSync(sessionPath) } catch { /* ok */ }
    try { fs.unlinkSync(outputPath) } catch { /* ok */ }
    try { fs.rmdirSync(tmpDir) } catch { /* ok */ }
}

main().catch((err) => {
    process.stderr.write(JSON.stringify({ error: `Unexpected error: ${err.message}` }) + '\n')
    process.exit(1)
})
