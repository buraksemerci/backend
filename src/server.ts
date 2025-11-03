import app from './app';

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`[Server]: Sunucu http://localhost:${PORT} adresinde çalışıyor`);
});