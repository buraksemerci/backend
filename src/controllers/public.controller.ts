// Dosya: src/controllers/public.controller.ts
import { Request, Response } from 'express';
import * as publicService from '../services/public.service';
import logger from '../utils/logger';

/**
 * A generic helper to run a service function
 * to avoid repeated try/catch blocks.
 */
const handleRequest = (
    serviceFunction: (languageCode: string) => Promise<any>
) => async (req: Request, res: Response) => {
    try {
        const languageCode = (req.query.lang as string) || 'tr';
        const data = await serviceFunction(languageCode);

        return res.status(200).json({ status: 'success', data });
    } catch (error: any) {
        logger.error(error, `Public Data Error (${serviceFunction.name})`);
        throw error; // Forward to global error handler
    }
};

// Create a handler for each service
export const getEquipment = handleRequest(publicService.getEquipmentService);
export const getBodyParts = handleRequest(publicService.getBodyPartsService);
export const getLocations = handleRequest(publicService.getLocationsService);
export const getLimitations = handleRequest(publicService.getLimitationsService);