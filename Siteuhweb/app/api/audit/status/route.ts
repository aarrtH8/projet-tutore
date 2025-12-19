import { NextResponse } from 'next/server'

import { getAuditStatus } from '@/lib/audit-runner'

export async function GET() {
  const status = await getAuditStatus()
  return NextResponse.json(status)
}
