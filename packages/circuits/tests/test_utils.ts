import { hashPersonalMessage, ecsign } from "@ethereumjs/util";
import { computeEffEcdsaPubInput } from "@personaelabs/spartan-ecdsa";
import { Poseidon, Tree } from "@personaelabs/spartan-ecdsa";
import { privateToAddress } from '@ethereumjs/util';

export const getEffEcdsaCircuitInput = (privKey: Buffer, msg: Buffer) => {
  const msgHash = hashPersonalMessage(msg);
  const { v, r: _r, s } = ecsign(msgHash, privKey);
  const r = BigInt("0x" + _r.toString("hex"));

  const circuitPubInput = computeEffEcdsaPubInput(r, v, msgHash);
  const input = {
    s: BigInt("0x" + s.toString("hex")),
    Tx: circuitPubInput.Tx,
    Ty: circuitPubInput.Ty,
    Ux: circuitPubInput.Ux,
    Uy: circuitPubInput.Uy
  };

  return input;
};

export const bytesToBigInt = (bytes: Uint8Array): bigint =>
  BigInt("0x" + Buffer.from(bytes).toString("hex"));

export function between(min: number, max: number) {
  return Math.floor(
    Math.random() * (max - min) + min
  )
}



export const createMerkleProof = (treeDepth: number, poseidon: Poseidon, privKeys: Buffer[], proverPrivKey: Buffer) => {
  const kvTree = new Tree(treeDepth, poseidon);
  const kvDatas = privKeys.map((val) => (
    {
      privKey: val,
      address: "0x" + privateToAddress(val).toString("hex"),
      sourceValue: between(1000000, 10000000),
      claimValue: between(10000, 100000),
    }
  ))

  let proverKvHash;
  let proverSourceValue = 0;
  let proverClaimValue = 0;


  // Insert the members into the tree
  for (const kvData of kvDatas) {
    const kvHash = poseidon.hash([
      BigInt(kvData.address),
      BigInt(kvData.sourceValue)
    ]);
    kvTree.insert(kvHash);

    // Set prover's public key hash for the reference below
    if (proverPrivKey === kvData.privKey) {
      proverKvHash = kvHash;
      proverSourceValue = kvData.sourceValue;
      proverClaimValue = kvData.claimValue;
    };
  }

  const index = kvTree.indexOf(proverKvHash as bigint);
  const merkleProof = kvTree.createProof(index);

  return { merkleProof, proverSourceValue, proverClaimValue };
}