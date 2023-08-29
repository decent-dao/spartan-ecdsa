import { PublicInput } from "./helpers/public_input";
import { PublicInput as LumenPublicInput } from "./helpers/kv_public_input";
// The same structure as MerkleProof in @zk-kit/incremental-merkle-tree.
// Not directly using MerkleProof defined in @zk-kit/incremental-merkle-tree so
// library users can choose whatever merkle tree management method they want.
export interface MerkleProof {
  root: bigint;
  siblings: [bigint][];
  pathIndices: number[];
}
export interface EffECDSAPubInput {
  Tx: bigint;
  Ty: bigint;
  Ux: bigint;
  Uy: bigint;
}

export interface NIZK {
  proof: Uint8Array;
  publicInput: PublicInput;
}

export interface ProverConfig {
  witnessGenWasm: string;
  circuit: string;
  enableProfiler?: boolean;
}

export interface VerifyConfig {
  circuit: string; // Path to circuit file compiled by Nova-Scotia
  enableProfiler?: boolean;
}

export interface IProver {
  circuit: string; // Path to circuit file compiled by Nova-Scotia
  witnessGenWasm: string; // Path to witness generator wasm file generated by Circom

  prove(...args: any): Promise<NIZK>;
}

export interface IVerifier {
  circuit: string; // Path to circuit file compiled by Nova-Scotia

  verify(proof: Uint8Array, publicInput: Uint8Array): Promise<boolean>;
}

export interface LumenNIZK {
  proof: Uint8Array;
  publicInput: LumenPublicInput;
}
