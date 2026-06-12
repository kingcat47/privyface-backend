import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ZkpModule } from './zkp/zkp.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // 전역으로 설정하여 모든 모듈에서 사용 가능
      envFilePath: '.env', // .env 파일 경로
    }),
    ZkpModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
