import dotenv from 'dotenv';
dotenv.config(); // <-- EN ÜSTE TAŞIYIN

import express from 'express';
import cors from 'cors';
import apiRouter from './api/index';

const app = express();

// Güvenilir proxy (Render, Heroku, Nginx vb. arkasındaysa)
// Bu, req.ip'nin doğru çalışması için GEREKLİDİR.
app.set('trust proxy', 1);

app.use(express.json());
app.use(cors());

// Basit bir "health check" endpoint'i
app.get('/health', (req, res) => {
    res.status(200).send('API is healthy and running!');
});

// === ANA API YÖNLENDİRMESİ ===
app.use('/api/v1', apiRouter);

export default app;
