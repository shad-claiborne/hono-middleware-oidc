/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import { playwright } from '@vitest/browser-playwright'

export default defineConfig({
    test: {
        setupFiles: './vitest.setup.ts',
        include: ['tests/**/*.{test,spec}.{ts,js}']
    },
})