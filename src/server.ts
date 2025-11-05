// Dosya: src/server.ts
import app from './app';
import { env } from './utils/env'; // <-- NEW: Validated ENV variables
import logger from './utils/logger'; // <-- NEW: Logger

try {
    // 1. Validate .env file. If missing, app crashes here.
    env;
    logger.info('All environment variables validated successfully.');

    // 2. Start the server
    const PORT = env.PORT;
    app.listen(PORT, () => {
        logger.info(`[Server]: Server is running at http://localhost:${PORT}`);
    });

} catch (error) {
    // This block catches failure from Zod's env validation
    logger.error(error, '.env validation failed. Server cannot start.');
    process.exit(1); // Exit with failure
}