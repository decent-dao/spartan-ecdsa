import { Profiler } from "../helpers/profiler";
import { IProver, MerkleProof, LumenNIZK, ProverConfig } from "../types";
import { loadCircuit, fromSig, snarkJsWitnessGen } from "../helpers/utils";
import {
  PublicInput,
  computeEffEcdsaPubInput,
  KVCircuitPubInput
} from "../helpers/KvPublicInput";
import wasm, { init } from "../wasm";


/**
 * ECDSA Membership Prover
 */
export class KVMembershipSecretProver extends Profiler implements IProver {
  circuit: string;
  witnessGenWasm: string;

  constructor(options: ProverConfig) {
    super({ enabled: options?.enableProfiler });


    const isNode = typeof window === "undefined";
    if (isNode) {
      if (
        options.circuit.includes("http") ||
        options.witnessGenWasm.includes("http")
      ) {
        throw new Error(
          `An URL was given for circuit/witnessGenWasm in Node.js environment. Please specify a local path.
          `
        );
      }
    }

    this.circuit = options.circuit;
    this.witnessGenWasm = options.witnessGenWasm;
  }

  async initWasm() {
    await init();
  }

  // @ts-ignore
  async prove(
    sig: string,
    msgHash: Buffer,
    merkleProof: MerkleProof,
    claimValue: bigint,
    sourceValue: bigint,
    secret: bigint,
    hashPubKeySecret: bigint,
    hashSecret: bigint
  ): Promise<LumenNIZK> {
    const { r, s, v } = fromSig(sig);

    const effEcdsaPubInput = computeEffEcdsaPubInput(r, v, msgHash);
    const circuitPubInput = new KVCircuitPubInput(
      merkleProof.root,
      effEcdsaPubInput.Tx,
      effEcdsaPubInput.Ty,
      effEcdsaPubInput.Ux,
      effEcdsaPubInput.Uy,
      claimValue,
      hashPubKeySecret,
      hashSecret,
    );
    const publicInput = new PublicInput(r, v, msgHash, circuitPubInput);

    const witnessGenInput = {
      s,
      ...merkleProof,
      ...effEcdsaPubInput,
      sourceValue,
      claimValue,
      secret,
      hashPubKeySecret,
      hashSecret,
    };

    this.time("Generate witness");

    const witness = await snarkJsWitnessGen(
      witnessGenInput,
      this.witnessGenWasm
    )
    this.timeEnd("Generate witness");

    this.time("Load circuit");
    const circuitBin = await loadCircuit(this.circuit);
    this.timeEnd("Load circuit");

    // Get the public input in bytes
    const circuitPublicInput: Uint8Array =
      publicInput.circuitPubInput.serialize();

    this.time("Prove");
    let proof = wasm.prove(circuitBin, witness.data, circuitPublicInput);
    this.timeEnd("Prove");

    return {
      proof,
      publicInput
    };

  }
}
