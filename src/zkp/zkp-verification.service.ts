import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Field, Poseidon, Proof, VerificationKey } from 'o1js';
import { FaceVerificationProgram } from './circuits/face-verification-program';
import { VerifyIdentityDto } from './dto/verify-identity.dto';

@Injectable()
export class ZkpVerificationService {
  private readonly logger = new Logger(ZkpVerificationService.name);

  constructor(private readonly configService: ConfigService) {}

  /**
   * 신원 검증 (Merkle + ZKP)
   */
  async verifyIdentity(dto: VerifyIdentityDto): Promise<{
    isValid: boolean;
    message: string;
  }> {
    try {
      // 프론트엔드에서 받은 전체 데이터 로그
      this.logger.log('═══════════════════════════════════════════════════');
      this.logger.log('프론트엔드에서 받은 요청 데이터');
      this.logger.log('═══════════════════════════════════════════════════');
      this.logger.log('Merkle Proof:', {
        leafHash: dto.merkleProof.leafHash,
        siblings: dto.merkleProof.siblings,
        siblingsCount: dto.merkleProof.siblings.length,
        isLeft: dto.merkleProof.isLeft,
        isLeftCount: dto.merkleProof.isLeft.length,
      });
      this.logger.log('Face ZK Proof:', {
        proofLength: dto.faceZkProof.proof.length,
        proofPrefix: dto.faceZkProof.proof.substring(0, 50) + '...',
        publicInput: dto.faceZkProof.publicInput,
        verificationKeyLength: dto.faceZkProof.verificationKey.length,
        verificationKeyPrefix:
          dto.faceZkProof.verificationKey.substring(0, 50) + '...',
      });
      this.logger.log('═══════════════════════════════════════════════════');

      // 1. Merkle 검증: "DB에 등록된 유저?"
      this.logger.log('');
      this.logger.log('[1단계] Merkle Proof 검증 시작...');
      const isValidMerkle = await this.verifyMerkleProof(dto.merkleProof);

      if (!isValidMerkle) {
        this.logger.warn('[1단계] Merkle Proof 검증 실패');
        this.logger.log('═══════════════════════════════════════════════════');
        return {
          isValid: false,
          message: 'Invalid Merkle proof - DB에 등록된 유저가 아닙니다',
        };
      }

      this.logger.log('[1단계] Merkle Proof 검증 성공');
      this.logger.log('');

      // 2. ZKP 검증: "얼굴 유사도 > 0.85?"
      this.logger.log('[2단계] Face ZK Proof 검증 시작...');
      const isValidFace = await this.verifyFaceZkProof(dto.faceZkProof);

      if (!isValidFace) {
        this.logger.warn('[2단계] Face ZK Proof 검증 실패');
        this.logger.log('═══════════════════════════════════════════════════');
        return {
          isValid: false,
          message:
            'Invalid face similarity proof - 얼굴 유사도 증명이 유효하지 않습니다',
        };
      }

      this.logger.log('[2단계] Face ZK Proof 검증 성공');
      this.logger.log('');
      this.logger.log('═══════════════════════════════════════════════════');
      this.logger.log('최종 결과: 신원 확인 성공');
      this.logger.log('═══════════════════════════════════════════════════');

      return {
        isValid: true,
        message: 'Identity verified - 신원 확인 성공',
      };
    } catch (error) {
      this.logger.error(`검증 오류: ${error.message}`, error.stack);
      this.logger.log('═══════════════════════════════════════════════════');
      return {
        isValid: false,
        message: `검증 오류: ${error.message}`,
      };
    }
  }

  /**
   * Merkle 검증 (Poseidon 해시 사용)
   * leafHash가 DB 루트에 속하는지 확인
   */
  private async verifyMerkleProof(proof: {
    leafHash: string;
    siblings: string[];
    isLeft: boolean[];
  }): Promise<boolean> {
    try {
      // .env 파일에서 머클 루트 가져오기
      const merkleRoot = this.configService.get<string>('MERKLE_ROOT');

      if (!merkleRoot) {
        this.logger.error('MERKLE_ROOT가 .env 파일에 설정되지 않았습니다');
        return false;
      }

      // 현재 해시를 leafHash로 시작
      let currentHash = Field(proof.leafHash);

      // siblings와 isLeft를 사용하여 루트까지 계산
      for (let i = 0; i < proof.siblings.length; i++) {
        const sibling = Field(proof.siblings[i]);
        const isLeft = proof.isLeft[i];

        if (isLeft) {
          // 왼쪽 자식(현재) + 오른쪽 자식(sibling)
          currentHash = Poseidon.hash([currentHash, sibling]);
        } else {
          // 왼쪽 자식(sibling) + 오른쪽 자식(현재)
          currentHash = Poseidon.hash([sibling, currentHash]);
        }
      }

      // 계산된 루트와 DB 루트 비교
      const computedRoot = currentHash.toString();
      const isValid = computedRoot === merkleRoot;

      if (!isValid) {
        this.logger.warn(
          `Merkle 루트 불일치 - 계산: ${computedRoot}, DB: ${merkleRoot}`,
        );
      }

      return isValid;
    } catch (error) {
      this.logger.error(`Merkle 검증 오류: ${error.message}`, error.stack);
      return false;
    }
  }

  /**
   * o1js ZKP 검증 - 간소화된 구현
   */
  private async verifyFaceZkProof(zkProof: {
    proof: string;
    publicInput: string[];
    verificationKey: string;
  }): Promise<boolean> {
    try {
      this.logger.log('───────────────────────────────────────────────────');
      this.logger.log('[2-1] ZKP 검증 시작');
      this.logger.log('───────────────────────────────────────────────────');

      // 1. Public Input 확인
      this.logger.log('[2-1-1] Public Input 확인');
      this.logger.log('  - 받은 publicInput:', zkProof.publicInput);
      this.logger.log('  - publicInput[0]:', zkProof.publicInput[0]);
      this.logger.log('  - 기대값: "1" (유사도 >= 0.85)');

      if (zkProof.publicInput[0] !== '1') {
        this.logger.warn('  Public Input 검증 실패: 유사도 < 0.85');
        this.logger.log('───────────────────────────────────────────────────');
        return false;
      }
      this.logger.log('  Public Input 검증 통과');

      // 2. VerificationKey 복원 (JSON)
      this.logger.log('');
      this.logger.log('[2-1-2] VerificationKey 복원');
      this.logger.log(
        '  - verificationKey 길이:',
        zkProof.verificationKey.length,
      );
      this.logger.log(
        '  - verificationKey 미리보기:',
        zkProof.verificationKey.substring(0, 100) + '...',
      );

      let vkData: any;
      try {
        vkData = JSON.parse(zkProof.verificationKey);
        this.logger.log('  VerificationKey JSON 파싱 성공');
        this.logger.log('  - verificationKey 구조:', {
          data: vkData.data ? '존재' : '없음',
          hash: vkData.hash ? '존재' : '없음',
          keys: Object.keys(vkData),
        });
      } catch (parseError: any) {
        this.logger.error(
          '  VerificationKey JSON 파싱 실패:',
          parseError.message,
        );
        this.logger.log('───────────────────────────────────────────────────');
        return false;
      }

      let verificationKey: VerificationKey;
      try {
        verificationKey = VerificationKey.fromJSON(vkData);
        this.logger.log('  VerificationKey 객체 생성 성공');
      } catch (vkError: any) {
        this.logger.error('  VerificationKey 객체 생성 실패:', vkError.message);
        this.logger.log('───────────────────────────────────────────────────');
        return false;
      }

      // 3. JsonProof 파싱
      this.logger.log('');
      this.logger.log('[2-1-3] Proof JSON 파싱');
      this.logger.log('  - proof 문자열 길이:', zkProof.proof.length);
      this.logger.log(
        '  - proof 미리보기:',
        zkProof.proof.substring(0, 100) + '...',
      );

      let jsonProof: any;
      try {
        jsonProof = JSON.parse(zkProof.proof);
        this.logger.log('  Proof JSON 파싱 성공');
        this.logger.log('  - jsonProof 구조:', {
          maxProofsVerified: jsonProof.maxProofsVerified,
          proof: jsonProof.proof ? `길이: ${jsonProof.proof.length}` : '없음',
          publicInput: jsonProof.publicInput,
          publicOutput: jsonProof.publicOutput,
          keys: Object.keys(jsonProof),
        });
      } catch (parseError: any) {
        this.logger.error('  Proof JSON 파싱 실패:', parseError.message);
        this.logger.error('  - 오류 위치:', parseError.stack);
        this.logger.log('───────────────────────────────────────────────────');
        return false;
      }

      // 4. FaceVerificationProgram.Proof로 복원 (동일 ZkProgram!)
      this.logger.log('');
      this.logger.log('[2-1-4] Proof 객체 복원');
      this.logger.log('  - 사용할 ZkProgram: FaceVerificationProgram');
      this.logger.log('  - Proof.fromJSON() 호출 중...');

      let faceProof: Proof<any, any>;
      try {
        faceProof = await FaceVerificationProgram.Proof.fromJSON(jsonProof);
        this.logger.log('  Proof 객체 복원 성공');
        this.logger.log('  - Proof 타입:', faceProof.constructor.name);
      } catch (restoreError: any) {
        this.logger.error('  Proof 객체 복원 실패:', restoreError.message);
        this.logger.error('  - 오류 상세:', restoreError.stack);
        this.logger.log('───────────────────────────────────────────────────');
        return false;
      }

      // 5. 공식 검증
      this.logger.log('');
      this.logger.log('[2-1-5] PLONK/KZG 검증 실행');
      this.logger.log('  - Public Input Field 변환 중...');
      const publicInput = zkProof.publicInput.map((input) => Field(input));
      this.logger.log(
        '  - 변환된 publicInput:',
        publicInput.map((f) => f.toString()),
      );

      // proof.verify()는 인자를 받지 않고, 성공 시 void, 실패 시 예외를 던짐
      this.logger.log('  - proof.verify() 호출 중...');
      try {
        await faceProof.verify();
        this.logger.log('  ZKP 검증 성공!');
        this.logger.log('───────────────────────────────────────────────────');
        return true;
      } catch (verifyError: any) {
        this.logger.error('  ZKP 검증 실패:', verifyError.message);
        this.logger.error('  - 오류 상세:', verifyError.stack);
        this.logger.log('───────────────────────────────────────────────────');
        return false;
      }
    } catch (error: any) {
      this.logger.error('ZKP 검증 전체 오류:', error.message);
      this.logger.error('  - 오류 상세:', error.stack);
      this.logger.log('───────────────────────────────────────────────────');
      return false;
    }
  }
}
