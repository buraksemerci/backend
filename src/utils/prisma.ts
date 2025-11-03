import { PrismaClient } from '@prisma/client';

// PrismaClient'in tek bir örneğini oluştur
const prisma = new PrismaClient();

// Bu örneği dışa aktar
export default prisma;