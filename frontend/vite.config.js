/// <reference types="vitest/config" />
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '')
  const proxyTarget = env.VITE_PROXY_TARGET || 'http://localhost:8080'

  return {
    plugins: [react()],
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: './src/setupTests.js',
      css: true,
      env: {
        VITE_API_URL: 'http://test.example.com',
      },
      coverage: {
        provider: 'v8',
        reporter: ['lcov', 'text'],
        reportsDirectory: './coverage',
      },
    },
    server: {
      host: true, // Esto permite que el puerto sea accesible desde fuera del contenedor
      port: 5173,
      watch: {
        usePolling: true, // Necesario para que Docker detecte cambios en sistemas de archivos Windows/Mac
      },
      strictPort: true, // Si el puerto está ocupado, falla en lugar de intentar con otro
      proxy: {
        '/api': {
          target: proxyTarget,
          changeOrigin: true,
        },
      },
    },
  }
})
