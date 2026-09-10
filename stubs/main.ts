import { fileURLToPath } from 'node:url'

/**
 * Path to the root directory where stubs are stored.
 */
export const stubsRoot = fileURLToPath(new URL('./', import.meta.url))
