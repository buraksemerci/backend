import { Request, Response, NextFunction } from 'express';
import { z, ZodError, ZodTypeAny } from 'zod';

// Bu fonksiyon, bir Zod şeması alan bir middleware fonksiyonu döndürür
export const validate =
    (schema: ZodTypeAny) =>
        (req: Request, res: Response, next: NextFunction) => {
            try {
                // Gelen isteğin body, query ve params'larını şemaya göre parse et
                schema.parse({
                    body: req.body,
                    query: req.query,
                    params: req.params,
                });

                // Doğrulama başarılıysa, bir sonraki adıma (controller'a) geç
                next();
            } catch (error) {
                if (error instanceof ZodError) {
                    // Zod'un detaylı hata mesajlarını topla
                    const errorMessages = error.issues.map((issue: z.ZodIssue) => ({
                        message: issue.message,
                        path: issue.path.join('.'),
                    }));

                    return res.status(400).json({
                        status: 'error',
                        errors: errorMessages,
                    });
                }

                // Beklenmedik bir hata olursa
                return res.status(500).json({
                    status: 'error',
                    message: 'Internal Server Error',
                });
            }
        };
