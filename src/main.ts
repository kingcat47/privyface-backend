import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // CORS 활성화 (프론트엔드에서 요청 가능하도록)
  app.enableCors({
    origin: true, // 모든 origin 허용 (개발 환경)
    credentials: true,
  });

  const port = process.env.PORT ?? 3000;
  await app.listen(port);
  console.log(`🚀 서버가 http://localhost:${port} 에서 실행 중입니다`);
  console.log(`📡 ZKP 검증 API: http://localhost:${port}/zkp/verify`);
}
bootstrap();
