import { cookies } from 'next/headers'

export type UserRole = 'admin' | 'client'

export interface User {
  id: string
  username: string
  role: UserRole
}

// Mock user database
const users: { username: string; password: string; role: UserRole }[] = [
  { username: 'admin', password: 'admin123', role: 'admin' },
  { username: 'client', password: 'client123', role: 'client' },
]

// Rate limiting store (in production, use Redis or database)
const loginAttempts: Map<string, { count: number; timestamp: number }> = new Map()

export async function validateCredentials(
  username: string,
  password: string
): Promise<{ success: boolean; user?: User; error?: string }> {
  // Check rate limiting
  const attempts = loginAttempts.get(username)
  const now = Date.now()
  
  if (attempts) {
    const timeDiff = now - attempts.timestamp
    if (timeDiff < 15 * 60 * 1000) { // 15 minutes
      if (attempts.count >= 5) {
        return { success: false, error: 'Trop de tentatives. Veuillez réessayer dans 15 minutes.' }
      }
    } else {
      // Reset after 15 minutes
      loginAttempts.delete(username)
    }
  }

  // Validate credentials
  const user = users.find((u) => u.username === username && u.password === password)

  if (!user) {
    // Increment failed attempts
    const currentAttempts = loginAttempts.get(username) || { count: 0, timestamp: now }
    loginAttempts.set(username, { count: currentAttempts.count + 1, timestamp: now })
    return { success: false, error: 'Nom d\'utilisateur ou mot de passe incorrect' }
  }

  // Reset attempts on successful login
  loginAttempts.delete(username)

  return {
    success: true,
    user: {
      id: `${user.username}-${Date.now()}`,
      username: user.username,
      role: user.role,
    },
  }
}

export async function getSession(): Promise<User | null> {
  const cookieStore = await cookies()
  const sessionCookie = cookieStore.get('session')

  if (!sessionCookie) {
    return null
  }

  try {
    const session = JSON.parse(sessionCookie.value)
    // Check if session is expired (30 minutes)
    if (Date.now() - session.timestamp > 30 * 60 * 1000) {
      return null
    }
    return session.user
  } catch {
    return null
  }
}

export async function createSession(user: User) {
  const cookieStore = await cookies()
  const session = {
    user,
    timestamp: Date.now(),
  }
  cookieStore.set('session', JSON.stringify(session), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 30 * 60, // 30 minutes
  })
}

export async function clearSession() {
  const cookieStore = await cookies()
  cookieStore.delete('session')
}
