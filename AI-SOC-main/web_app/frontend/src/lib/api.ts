import axios from 'axios'

const baseURL =
  import.meta.env.VITE_API_URL?.replace(/\/$/, '') || 'http://localhost:8001'

export const api = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 25_000,
})

let getAccessToken: () => string | null = () => null

/** Call once at app init (see `main.tsx`) to attach JWT from auth store without circular imports. */
export function registerAuthTokenGetter(fn: () => string | null) {
  getAccessToken = fn
}

api.interceptors.request.use((config) => {
  const token = getAccessToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})
