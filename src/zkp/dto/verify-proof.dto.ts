export class VerifyProofDto {
  timestamp: number;
  proofType: 'o1js' | 'snarkjs';
  publicInput: string[];
  maxProofsVerified: number;
  proof: string; // base64 인코딩된 Proof 문자열
}
