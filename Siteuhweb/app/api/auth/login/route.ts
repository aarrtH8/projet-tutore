import { NextRequest, NextResponse } from 'next/server'
import { validateCredentials, createSession } from '@/lib/auth'

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json()

    if (!username || !password) {
      return NextResponse.json(
        { success: false, error: 'Nom d\'utilisateur et mot de passe requis' },
        { status: 400 }
      )
    }

    const result = await validateCredentials(username, password)

    if (result.success && result.user) {
      await createSession(result.user)
      return NextResponse.json({ success: true, user: result.user })
    }

    return NextResponse.json(
      { success: false, error: result.error },
      { status: 401 }
    )
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Erreur serveur' },
      { status: 500 }
    )
  }
}
