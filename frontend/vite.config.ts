import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
      '/stats': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
      '/mode': 'http://localhost:8000',
      '/api': 'http://localhost:8000',
      '/block': 'http://localhost:8000',
      '/blocked': 'http://localhost:8000',
      '/unblock': 'http://localhost:8000',
    },
  },
})
