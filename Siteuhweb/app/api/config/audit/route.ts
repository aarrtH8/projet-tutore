import { NextResponse } from 'next/server'

import { getAuditConfig, saveAuditConfig } from '@/lib/audit-config'

export async function GET() {
  const config = await getAuditConfig()
  return NextResponse.json(config)
}

export async function PUT(request: Request) {
  try {
    const payload = await request.json()
    const updated = await saveAuditConfig(payload)
    return NextResponse.json(updated)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Impossible d’enregistrer la configuration'
    return NextResponse.json({ error: message }, { status: 400 })
  }
}
