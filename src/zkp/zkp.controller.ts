import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { ZkpVerificationService } from './zkp-verification.service';
import { VerifyIdentityDto } from './dto/verify-identity.dto';

@Controller('api')
export class ZkpController {
  constructor(private readonly zkpService: ZkpVerificationService) {}

  @Post('verify-identity')
  @HttpCode(HttpStatus.OK)
  async verifyIdentity(@Body() body: VerifyIdentityDto) {
    try {
      // 검증 수행
      const result = await this.zkpService.verifyIdentity(body);

      if (!result.isValid) {
        throw new HttpException(result.message, HttpStatus.UNAUTHORIZED);
      }

      return {
        success: true,
        message: result.message,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error.message || 'Verification failed',
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
