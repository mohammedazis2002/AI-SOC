import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { registerRequest } from '@/lib/auth-api'
import { useAppStore } from '@/store/useAppStore'

export function Register() {
  const addNotification = useAppStore((s) => s.addNotification)

  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      const res = await registerRequest(name, email, password)
      addNotification({ type: 'success', message: res.message })
    } catch (err: unknown) {
      const msg =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
          : undefined
      addNotification({
        type: 'error',
        message: typeof msg === 'string' ? msg : 'Registration failed.',
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[var(--bg-base)] flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <Shield className="h-10 w-10 text-blue-600" />
          </div>
          <CardTitle className="font-mono text-xl">Create account</CardTitle>
          <p className="text-sm text-slate-500">Register against the FastAPI backend</p>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label className="text-sm font-medium text-slate-700 block mb-1">Name</label>
              <Input value={name} onChange={(e) => setName(e.target.value)} required minLength={1} />
            </div>
            <div>
              <label className="text-sm font-medium text-slate-700 block mb-1">Email</label>
              <Input
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="text-sm font-medium text-slate-700 block mb-1">Password</label>
              <Input
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
              />
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Submitting…' : 'Register'}
            </Button>
          </form>
          <p className="text-sm text-slate-500 text-center mt-4">
            <Link to="/login" className="text-blue-600 font-medium hover:underline">
              Sign in
            </Link>
            {' · '}
            <Link to="/" className="text-slate-600 hover:underline">
              Back to app
            </Link>
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
