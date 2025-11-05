// src/middlewares/validate.ts
import { Request, Response, NextFunction } from 'express';
import { ZodTypeAny } from 'zod';

// Bu fonksiyon, bir Zod şeması alan bir middleware fonksiyonu döndürür
export const validate =
    (schema: ZodTypeAny) =>
        (req: Request, res: Response, next: NextFunction) => {

            // --- BÜYÜK DEĞİŞİKLİK ---
            // Artık 'try...catch' bloğuna ihtiyacımız yok.
            // 1. 'schema.parse' başarısız olduğunda, Express 5'in
            //    yeni hata yakalama mekanizması (veya 'express-async-errors')
            //    bu hatayı (ZodError) otomatik olarak yakalar.
            // 2. Bu hatayı 'next(error)' ile bizim global error handler'ımıza (app.ts içinde) gönderir.
            // 3. Global error handler, 'instanceof ZodError' kontrolünü yapar
            //    ve güzel formatlanmış 400 Bad Request hatasını döndürür.

            // Gelen isteğin body, query ve params'larını şemaya göre parse et
            schema.parse({
                body: req.body,
                query: req.query,
                params: req.params,
            });

            // Doğrulama başarılıysa, bir sonraki adıma (controller'a) geç
            next();

            // --- 'try...catch' BLOĞU TAMAMEN KALDIRILDI ---
        };