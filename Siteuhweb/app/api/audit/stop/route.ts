import { NextResponse } from 'next/server'

import { stopAudit } from '@/lib/audit-runner'

export async function POST() {
  const status = await stopAudit()
  return NextResponse.json(status)
}
