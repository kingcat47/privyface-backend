import { Field, Poseidon, Struct, Bool, Provable, ZkProgram } from 'o1js';

// 클라이언트와 동일한 구조체 정의
export class FaceFeatures extends Struct({
  governmentFeatures: Provable.Array(Field, 10),
  userFeatures: Provable.Array(Field, 10),
  threshold: Field,
}) {
  calculateEuclideanDistance(): Field {
    let sum = Field(0);
    for (let i = 0; i < this.governmentFeatures.length; i++) {
      const diff = this.governmentFeatures[i].sub(this.userFeatures[i]);
      sum = sum.add(diff.mul(diff));
    }
    return sum;
  }

  isSimilar(): Bool {
    const distance = this.calculateEuclideanDistance();
    return distance.lessThanOrEqual(this.threshold);
  }
}

export class MerklePath extends Struct({
  pathElements: Provable.Array(Field, 2),
  pathIndices: Provable.Array(Field, 2),
  root: Field,
}) {
  computeRoot(leaf: Field): Field {
    let current = leaf;
    for (let i = 0; i < this.pathElements.length; i++) {
      const sibling = this.pathElements[i];
      const direction = this.pathIndices[i];
      const left = current;
      const right = sibling;
      const hashLeft = Poseidon.hash([left, right]);
      const hashRight = Poseidon.hash([right, left]);
      current = Provable.if(direction.equals(0), hashLeft, hashRight);
    }
    return current;
  }
}

// 클라이언트와 동일한 ZkProgram 정의
export const FaceVerificationProgram = ZkProgram({
  name: 'FaceVerification',
  publicInput: Field,
  methods: {
    prove: {
      privateInputs: [FaceFeatures, MerklePath],
      async method(
        root: Field,
        features: FaceFeatures,
        merklePath: MerklePath,
      ): Promise<void> {
        const isSimilar = features.isSimilar();
        const leaf = Poseidon.hash(features.governmentFeatures);
        const computedRoot = merklePath.computeRoot(leaf);
        const rootMatches = computedRoot.equals(root);

        isSimilar.assertTrue('얼굴 유사도가 임계값을 초과했습니다');
        rootMatches.assertTrue('머클 루트가 일치하지 않습니다');
      },
    },
  },
});
