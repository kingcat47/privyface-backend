export class MerkleProofDto {
  leafHash: string; // Poseidon 해시된 featureHash
  siblings: string[]; // pathElements
  isLeft: boolean[]; // 자기 노드가 왼쪽인지
}

export class FaceZkProofDto {
  proof: string; // o1js base64 인코딩된 Proof 문자열
  publicInput: string[]; // ["1"] - 유사도 통과 = "1"
  verificationKey: string; // JSON 문자열
}

export class VerifyIdentityDto {
  merkleProof: MerkleProofDto;
  faceZkProof: FaceZkProofDto;
}
