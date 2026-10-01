import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { registerAuthTokenGetter } from '@/lib/api'
import { useAuthStore } from '@/store/authStore'

registerAuthTokenGetter(() => useAuthStore.getState().token)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
