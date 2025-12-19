#!/usr/bin/env node
/**
 * Panoptis privileged scan service
 * --------------------------------
 * This process must be launched with elevated privileges (e.g. via systemd).
 * It exposes a simple JSON-over-UNIX-socket protocol that runs the requested
 * command and streams stdout/stderr back to the client.
 */

const fs = require('fs')
const net = require('net')
const path = require('path')
const { spawn } = require('child_process')

const socketPath = process.env.PANOPTIS_SCAN_SOCKET || '/tmp/panoptis-scan.sock'

function cleanupAndExit(code) {
  try {
    if (fs.existsSync(socketPath)) {
      fs.unlinkSync(socketPath)
    }
  } catch (error) {
    console.error('[panoptis-scan-service] Unable to remove socket:', error)
  }
  process.exit(code)
}

if (fs.existsSync(socketPath)) {
  try {
    fs.unlinkSync(socketPath)
  } catch (error) {
    console.error(`[panoptis-scan-service] Cannot remove stale socket ${socketPath}:`, error)
    process.exit(1)
  }
}

const server = net.createServer((socket) => {
  let buffer = ''
  let requestHandled = false

  socket.setEncoding('utf-8')

  socket.on('data', (chunk) => {
    buffer += chunk
    if (requestHandled) {
      return
    }
    const newlineIndex = buffer.indexOf('\n')
    if (newlineIndex === -1) {
      return
    }
    requestHandled = true
    const payload = buffer.slice(0, newlineIndex)
    buffer = buffer.slice(newlineIndex + 1)
    handleRequest(socket, payload)
  })

  socket.on('error', (error) => {
    console.error('[panoptis-scan-service] Socket error:', error)
  })
})

server.listen(socketPath, () => {
  const mode = process.env.PANOPTIS_SCAN_SOCKET_MODE
    ? parseInt(process.env.PANOPTIS_SCAN_SOCKET_MODE, 8)
    : 0o666
  fs.chmodSync(socketPath, mode)
  console.log(`[panoptis-scan-service] Listening on ${socketPath}`)
})

server.on('error', (error) => {
  console.error('[panoptis-scan-service] Server error:', error)
  cleanupAndExit(1)
})

process.on('SIGINT', () => cleanupAndExit(0))
process.on('SIGTERM', () => cleanupAndExit(0))

function handleRequest(socket, payload) {
  let request
  try {
    request = JSON.parse(payload)
  } catch (error) {
    writeMessage(socket, { event: 'error', message: 'Invalid JSON payload' })
    socket.end()
    return
  }

  if (!request || !Array.isArray(request.command) || request.command.length === 0) {
    writeMessage(socket, { event: 'error', message: 'Missing command to execute' })
    socket.end()
    return
  }

  const cwd = typeof request.cwd === 'string' && request.cwd.length > 0 ? request.cwd : process.cwd()
  const env = { ...process.env, ...(request.env || {}) }

  const child = spawn(request.command[0], request.command.slice(1), {
    cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
  })

  child.stdout.on('data', (chunk) => {
    writeMessage(socket, { event: 'stdout', data: chunk.toString('utf-8') })
  })

  child.stderr.on('data', (chunk) => {
    writeMessage(socket, { event: 'stderr', data: chunk.toString('utf-8') })
  })

  child.on('close', (code, signal) => {
    writeMessage(socket, { event: 'exit', code, signal })
    socket.end()
  })

  child.on('error', (error) => {
    writeMessage(socket, { event: 'error', message: error.message })
    socket.end()
  })
}

function writeMessage(socket, payload) {
  try {
    socket.write(`${JSON.stringify(payload)}\n`)
  } catch (error) {
    console.error('[panoptis-scan-service] Failed to write message:', error)
  }
}
