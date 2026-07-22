export class MerkleProofDto {
  leafHash: string; // Poseidon 해시된 featureHash
  siblings: string[]; // pathElements
  isLeft: boolean[]; // 자기 노드가 왼쪽인지
}

export class FaceZkProofDto {
  proof: string;          // JSON.stringify된 groth16 proof 문자열
  publicSignals: string[]; // [root, threshold] — circom 회로의 public input
  // verificationKey는 서버 로컬 파일에서 로드 (클라이언트 수신 제거)
}

export class VerifyIdentityDto {
  merkleProof: MerkleProofDto;
  faceZkProof: FaceZkProofDto;
}
