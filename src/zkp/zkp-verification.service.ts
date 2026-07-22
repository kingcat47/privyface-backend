import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import * as fs from 'fs';
import * as path from 'path';
import { VerifyIdentityDto } from './dto/verify-identity.dto';

// verification_key.json을 서버 로컬에서 로드 (클라이언트에서 받지 않음)
const VERIFICATION_KEY = JSON.parse(
  fs.readFileSync(path.join(process.cwd(), 'circuits', 'verification_key.json'), 'utf-8'),
);

// 서버가 허용하는 threshold 고정값 (프론트의 config.ts와 동일해야 함)
// 공격자가 threshold를 임의로 바꾼 proof를 보내는 것을 차단
const EXPECTED_THRESHOLD = '800000';

@Injectable()
export class ZkpVerificationService {
  private readonly logger = new Logger(ZkpVerificationService.name);

  constructor(private readonly configService: ConfigService) {}

  async verifyIdentity(dto: VerifyIdentityDto): Promise<{
    isValid: boolean;
    message: string;
  }> {
    try {
      this.logger.log('═══════════════════════════════════════════════════');
      this.logger.log('프론트엔드에서 받은 요청 데이터');
      this.logger.log('═══════════════════════════════════════════════════');
      this.logger.log('Merkle Proof:', {
        leafHash: dto.merkleProof.leafHash,
        siblings: dto.merkleProof.siblings,
        isLeft: dto.merkleProof.isLeft,
      });
      this.logger.log('Face ZK Proof:', {
        proofLength: dto.faceZkProof.proof.length,
        publicSignals: dto.faceZkProof.publicSignals,
      });
      this.logger.log('═══════════════════════════════════════════════════');

      // 1. Merkle 검증
      this.logger.log('[1단계] Merkle Proof 검증 시작...');
      const isValidMerkle = await this.verifyMerkleProof(dto.merkleProof);

      if (!isValidMerkle) {
        this.logger.warn('[1단계] Merkle Proof 검증 실패');
        return {
          isValid: false,
          message: 'Invalid Merkle proof - DB에 등록된 유저가 아닙니다',
        };
      }
      this.logger.log('[1단계] Merkle Proof 검증 성공');

      // 2. ZKP 검증
      this.logger.log('[2단계] Face ZK Proof 검증 시작...');
      const isValidFace = await this.verifyFaceZkProof(dto.faceZkProof);

      if (!isValidFace) {
        this.logger.warn('[2단계] Face ZK Proof 검증 실패');
        return {
          isValid: false,
          message: 'Invalid face similarity proof - 얼굴 유사도 증명이 유효하지 않습니다',
        };
      }
      this.logger.log('[2단계] Face ZK Proof 검증 성공');
      this.logger.log('최종 결과: 신원 확인 성공');

      return { isValid: true, message: 'Identity verified - 신원 확인 성공' };
    } catch (error) {
      this.logger.error(`검증 오류: ${error.message}`, error.stack);
      return { isValid: false, message: `검증 오류: ${error.message}` };
    }
  }

  /**
   * Merkle 검증 — circomlibjs Poseidon (BN128 곡선) 사용
   * 프론트엔드의 UserInfo.ts 및 회로와 동일한 해시 함수
   */
  private async verifyMerkleProof(proof: {
    leafHash: string;
    siblings: string[];
    isLeft: boolean[];
  }): Promise<boolean> {
    try {
      const merkleRoot = this.configService.get<string>('MERKLE_ROOT');
      if (!merkleRoot) {
        this.logger.error('MERKLE_ROOT가 .env에 설정되지 않았습니다');
        return false;
      }

      // circomlibjs Poseidon: BigInt 배열 입력 → Uint8Array 출력
      // poseidon.F.toString()으로 10진수 문자열 변환
      const poseidon = await buildPoseidon();
      const hash = (...inputs: string[]) => {
        const result = poseidon(inputs.map(BigInt));
        return poseidon.F.toString(result);
      };

      let currentHash = proof.leafHash;

      for (let i = 0; i < proof.siblings.length; i++) {
        const sibling = proof.siblings[i];
        if (proof.isLeft[i]) {
          // 내가 왼쪽: Hash(나, 형제)
          currentHash = hash(currentHash, sibling);
        } else {
          // 내가 오른쪽: Hash(형제, 나)
          currentHash = hash(sibling, currentHash);
        }
      }

      const isValid = currentHash === merkleRoot.trim();
      if (!isValid) {
        this.logger.warn(`Merkle 루트 불일치 — 계산: ${currentHash}, .env: ${merkleRoot.trim()}`);
      }
      return isValid;
    } catch (error) {
      this.logger.error(`Merkle 검증 오류: ${error.message}`);
      return false;
    }
  }

  /**
   * Face ZKP 검증 — snarkjs groth16.verify() 사용
   * 프론트엔드에서 circom 회로로 생성한 groth16 proof 검증
   */
  private async verifyFaceZkProof(zkProof: {
    proof: string;
    publicSignals: string[];
  }): Promise<boolean> {
    try {
      // proof는 JSON.stringify된 문자열로 전송됨 → 파싱
      const proof = JSON.parse(zkProof.proof);
      const { publicSignals } = zkProof;

      this.logger.log('  - publicSignals:', publicSignals);
      this.logger.log('  - proof.protocol:', proof.protocol);

      // publicSignals = [root, threshold] (circom 회로 signal 선언 순서)
      // root와 threshold가 서버 기대값과 일치하는지 먼저 확인
      // → 공격자가 threshold를 부풀려서 아무 얼굴이나 통과시키는 공격 차단
      const expectedRoot = this.configService.get<string>('MERKLE_ROOT')?.trim();
      if (publicSignals[0] !== expectedRoot) {
        this.logger.warn(`루트 불일치 — proof: ${publicSignals[0]}, .env: ${expectedRoot}`);
        return false;
      }
      if (publicSignals[1] !== EXPECTED_THRESHOLD) {
        this.logger.warn(`threshold 불일치 — proof: ${publicSignals[1]}, 기대값: ${EXPECTED_THRESHOLD}`);
        return false;
      }

      // snarkjs.groth16.verify(vk, publicSignals, proof)
      // verificationKey는 서버 로컬 파일에서 로드한 VERIFICATION_KEY 사용
      const isValid = await snarkjs.groth16.verify(
        VERIFICATION_KEY,
        publicSignals,
        proof,
      );

      this.logger.log(`  - 검증 결과: ${isValid}`);
      return isValid;
    } catch (error) {
      this.logger.error(`ZKP 검증 오류: ${error.message}`);
      return false;
    }
  }
}
