# ZKP Face Verification Server

NestJS 기반의 영지식 증명(Zero-Knowledge Proof) 얼굴 신원 검증 백엔드 서버입니다.

얼굴 특징값을 서버에 전송하지 않고, **유사도 >= 0.85임을 증명하는 ZK Proof만 전송**하여 프라이버시를 보호하면서 신원을 검증합니다.

## 기술 스택

- **Framework**: NestJS
- **ZKP Library**: [o1js](https://github.com/o1-labs/o1js) (Mina Protocol)
- **Hash**: Poseidon Hash
- **Language**: TypeScript

## 동작 방식

신원 검증은 두 단계로 이루어집니다.

### 1단계: Merkle Proof 검증
- 클라이언트가 보낸 `leafHash`와 `siblings`를 Poseidon 해시로 루트까지 재계산
- 계산된 루트가 서버의 `MERKLE_ROOT`와 일치하면 통과 → **등록된 유저 확인**

### 2단계: Face ZK Proof 검증
- `publicInput[0] == "1"` 확인 → 얼굴 유사도 임계값 통과 여부
- `VerificationKey`, `Proof` 복원 후 `proof.verify()` 호출 → **암호학적 검증**

```
[클라이언트]
  얼굴 인식 → ZK Proof 생성 (o1js) + Merkle Path 계산
       ↓
  POST /api/verify-identity
       ↓
[서버]
  1. Merkle 루트 재계산 → MERKLE_ROOT 비교
  2. ZK Proof 암호학적 검증
       ↓
  성공 → { success: true }
  실패 → 401 / 400
```

## 시작하기

### 1. 설치

```bash
npm install
```

### 2. 환경 변수 설정

```bash
cp .env.example .env
```

`.env` 파일에 Merkle Root 값을 설정합니다.

```env
MERKLE_ROOT=your_merkle_root_here
```

### 3. 실행

```bash
# 개발 모드
npm run start:dev

# 프로덕션 모드
npm run start:prod
```

서버가 실행되면 `http://localhost:3000` 에서 접근 가능합니다.

## API

### `POST /api/verify-identity`

**Request Body**

```json
{
  "merkleProof": {
    "leafHash": "string",
    "siblings": ["string"],
    "isLeft": [true, false]
  },
  "faceZkProof": {
    "proof": "string (JSON)",
    "publicInput": ["1"],
    "verificationKey": "string (JSON)"
  }
}
```

**Response**

```json
// 성공 (200)
{ "success": true, "message": "Identity verified - 신원 확인 성공" }

// 실패 (401)
{ "message": "Invalid Merkle proof - DB에 등록된 유저가 아닙니다" }

// 실패 (401)
{ "message": "Invalid face similarity proof - 얼굴 유사도 증명이 유효하지 않습니다" }
```

## ZK 회로

`src/zkp/circuits/face-verification-program.ts`에 정의된 `ZkProgram`입니다.

- **FaceFeatures**: 얼굴 특징 벡터 10차원, 유클리드 거리로 유사도 판단
- **MerklePath**: 깊이 2의 Merkle 경로, Poseidon 해시로 루트 계산
- **prove**: 위 두 조건을 ZK 회로 내에서 검증, proof 생성은 클라이언트에서 수행
