import { setupServer } from 'msw/node';
import { httpHandlers } from './handlers';

/** Node-side MSW server for Vitest component tests. */
export const server = setupServer(...httpHandlers);
