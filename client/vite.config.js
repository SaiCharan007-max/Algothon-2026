import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // in dev the api runs separately, proxy so we don't need CORS / env vars
    proxy: { '/api': 'http://localhost:5050' },
  },
})
