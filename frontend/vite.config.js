import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Backend URL: use host.docker.internal when running inside Docker Compose,
// localhost when running directly on the host.
const BACKEND = process.env.VITE_BACKEND_HOST || 'localhost'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,  // bind to 0.0.0.0 — required for Docker and network access
    proxy: {
      '/api': {
        target: `http://${BACKEND}:8000`,
        changeOrigin: true
      },
      '/socket.io': {
        target: `http://${BACKEND}:8000`,
        changeOrigin: true,
        ws: true,
        rewriteWsOrigin: true
      }
    }
  }
})
