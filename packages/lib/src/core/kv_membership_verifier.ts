import { Profiler } from "../helpers/profiler";
import { loadCircuit } from "../helpers/utils";
import { IVerifier, VerifyConfig } from "../types";
import wasm, { init } from "../wasm";
import { PublicInput, verifyEffEcdsaPubInput } from "../helpers/kv_public_input";

/**
 * ECDSA Membership Verifier
 */
export class KVMembershipSecretVerifier extends Profiler implements IVerifier {
  circuit: string;

  constructor(options: VerifyConfig) {
    super({ enabled: options?.enableProfiler });

    this.circuit = options.circuit;
  }

  async initWasm() {
    await init();
  }

  async verify(
    proof: Uint8Array,
    publicInputSer: Uint8Array
  ): Promise<boolean> {
    this.time("Load circuit");
    const circuitBin = await loadCircuit(this.circuit);
    this.timeEnd("Load circuit");

    this.time("Verify public input");
    const publicInput = PublicInput.deserialize(publicInputSer);
    let isPubInputValid = false;
    let isProofValid;
    try {
      isPubInputValid = verifyEffEcdsaPubInput(publicInput);
    } catch (e) {
      return false;
    } finally {
      this.timeEnd("Verify public input");
    }

    this.time("Verify proof");
    try {
      isProofValid = await wasm.verify(
        circuitBin,
        proof,
        publicInput.circuitPubInput.serialize()
      );
    } catch (_e) {
      isProofValid = false;
    }

    this.timeEnd("Verify proof");
    return isProofValid && isPubInputValid;
  }
}
