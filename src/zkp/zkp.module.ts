import { Module } from '@nestjs/common';
import { ZkpController } from './zkp.controller';
import { ZkpVerificationService } from './zkp-verification.service';

@Module({
  controllers: [ZkpController],
  providers: [ZkpVerificationService],
})
export class ZkpModule {}
