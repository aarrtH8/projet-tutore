import { NextResponse } from 'next/server'

import { startAudit } from '@/lib/audit-runner'

export async function POST() {
  const status = await startAudit()
  return NextResponse.json(status)
}
