import { hashTypedData } from "viem";
import { Poseidon, Tree } from "../../src/lib";
import { privateToAddress } from "@ethereumjs/util";

const MESSAGE = "I attest ownership to this wallet";
export const DOMAIN = {
  name: "Attestation",
  version: "1",
  chainId: 1
};

export const CONTENT_TYPES = {
  Attestation: [{ name: "message", type: "string" }]
};

export const CONTENT_VALUES = {
  message: MESSAGE
};

export type PrefixedHex = `0x${string}`;
export type EIP712Types = {
  [key: string]: { name: string; type: string }[];
};

export type EIP712Value = {
  [key: string]: string | number;
};

export type EIP712TypedData = {
  domain: EIP712Domain;
  types: EIP712Types;
  value: EIP712Value;
};

export type EIP712Domain = {
  name: string;
  version: string;
  chainId: number;
  // verifyingContract: PrefixedHex;
};

export function between(min: number, max: number) {
  return Math.floor(Math.random() * (max - min) + min);
}

export function eip712MsgHash(
  domain: EIP712Domain,
  types: EIP712Types,
  value: EIP712Value
): Buffer {
  const hash = hashTypedData({
    domain,
    types,
    primaryType: Object.keys(types)[0],
    message: value
  });
  return Buffer.from(hash.replace("0x", ""), "hex");
}

export const createMerkleProof = (
  treeDepth: number,
  poseidon: Poseidon,
  privKeys: Buffer[],
  proverPrivKey: Buffer,
  proverClaimValue: number,
  proverSourceValue: number
) => {
  const kvTree = new Tree(treeDepth, poseidon);
  const kvDatas = privKeys.map(val => ({
    privKey: val,
    address: "0x" + privateToAddress(val).toString("hex"),
    sourceValue:
      val === proverPrivKey ? proverSourceValue : between(1000000, 10000000),
    claimValue:
      val === proverPrivKey ? proverClaimValue : between(10000, 100000)
  }));

  let proverKvHash;

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
    }
  }

  const index = kvTree.indexOf(proverKvHash as bigint);
  const merkleProof = kvTree.createProof(index);

  return { merkleProof };
};
