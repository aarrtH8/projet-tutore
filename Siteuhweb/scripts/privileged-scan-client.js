#!/usr/bin/env node
/**
 * Client utility that forwards a command to the privileged scan service.
 * Falls back to running the command locally if the service is unavailable.
 */

const net = require('net')
const path = require('path')
const { spawn } = require('child_process')

const args = process.argv.slice(2)

function parseArguments() {
  let socketPath = process.env.PANOPTIS_SCAN_SOCKET || '/tmp/panoptis-scan.sock'
  const dashIndex = args.indexOf('--')
  const command = dashIndex === -1 ? args : args.slice(dashIndex + 1)

  if (!command.length) {
    console.error('[privileged-scan-client] Aucun programme à exécuter.')
    process.exit(2)
  }

  return { socketPath, command }
}

const { socketPath, command } = parseArguments()

async function run() {
  try {
    const socket = await connectToService(socketPath)
    forwardCommand(socket)
  } catch (error) {
    console.error(
      `[privileged-scan-client] Service privilégié indisponible (${error.code || error.message}). ` +
        'Exécution locale sans privilèges…'
    )
    runLocal()
  }
}

function connectToService(pathname) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(pathname)
    const onError = (error) => {
      socket.destroy()
      reject(error)
    }
    socket.once('error', onError)
    socket.once('connect', () => {
      socket.removeListener('error', onError)
      resolve(socket)
    })
  })
}

function forwardCommand(socket) {
  const payload = {
    command,
    cwd: process.cwd(),
  }
  socket.write(`${JSON.stringify(payload)}\n`)

  let buffer = ''
  socket.on('data', (chunk) => {
    buffer += chunk.toString('utf-8')
    let index
    while ((index = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, index)
      buffer = buffer.slice(index + 1)
      if (!line.trim()) continue
      handleMessage(line)
    }
  })

  socket.on('error', (error) => {
    console.error('[privileged-scan-client] Erreur de communication:', error)
    process.exit(1)
  })

  socket.on('end', () => {
    // server ends connection after exit event
  })
}

function handleMessage(line) {
  let message
  try {
    message = JSON.parse(line)
  } catch {
    return
  }
  switch (message.event) {
    case 'stdout':
      if (typeof message.data === 'string') {
        process.stdout.write(message.data)
      }
      break
    case 'stderr':
      if (typeof message.data === 'string') {
        process.stderr.write(message.data)
      }
      break
    case 'error':
      if (message.message) {
        process.stderr.write(`[privileged-scan-service] ${message.message}\n`)
      }
      break
    case 'exit':
      process.exit(typeof message.code === 'number' ? message.code : message.signal ? 128 : 0)
      break
    default:
      break
  }
}

function runLocal() {
  const child = spawn(command[0], command.slice(1), {
    cwd: process.cwd(),
    env: process.env,
    stdio: ['inherit', 'pipe', 'pipe'],
    shell: false,
  })

  child.stdout.on('data', (chunk) => process.stdout.write(chunk))
  child.stderr.on('data', (chunk) => process.stderr.write(chunk))
  child.on('close', (code) => process.exit(code ?? 1))
  child.on('error', (error) => {
    console.error('[privileged-scan-client] Impossible de lancer la commande localement:', error)
    process.exit(1)
  })
}

run()
