const wasm_tester = require("circom_tester").wasm;
var EC = require("elliptic").ec;
import * as path from "path";
import { Poseidon } from "@personaelabs/spartan-ecdsa";
import { createMerkleProof, getEffEcdsaCircuitInput } from "./test_utils";
const ec = new EC("secp256k1");
describe("kv_membership", () => {
  it("should verify correct signature and merkle proof", async () => {
    // Compile the circuit
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/kv_membership_test.circom"),
      {
        prime: "secq256k1" // Specify to use the option --prime secq256k1 when compiling with circom
      }
    );

    // Construct the tree
    const poseidon = new Poseidon();
    await poseidon.initWasm();

    const nLevels = 20;

    const privKeys = [
      Buffer.from("".padStart(16, "🧙"), "utf16le"),
      Buffer.from("".padStart(16, "🪄"), "utf16le"),
      Buffer.from("".padStart(16, "🔮"), "utf16le")
    ];


    // Sign
    const index = 0; // Use privKeys[0] for proving
    const privKey = privKeys[index];
    const msg = Buffer.from("hello world");
    const secret = BigInt(`0x${Buffer.from("".padStart(16, "🧙"), "utf16le").toString("hex")}`);

    const pubKey = ec.keyFromPrivate(privKey.toString("hex")).getPublic();

    const hashPubKey = poseidon.hash([pubKey.x.toString("hex"), pubKey.y.toString("hex")]);
    const hashSecret = poseidon.hash([secret, BigInt(0)]);
    const hashPubKeySecret = poseidon.hash([hashPubKey, secret]);

    // Prepare signature proof input
    const effEcdsaInput = getEffEcdsaCircuitInput(privKey, msg);
    const { merkleProof, proverSourceValue, proverClaimValue } = createMerkleProof(nLevels, poseidon, privKeys, privKey);

    const input = {
      root: merkleProof.root,
      s: effEcdsaInput.s,
      Tx: effEcdsaInput.Tx,
      Ty: effEcdsaInput.Ty,
      Ux: effEcdsaInput.Ux,
      Uy: effEcdsaInput.Uy,
      siblings: merkleProof.siblings,
      pathIndices: merkleProof.pathIndices,
      sourceValue: BigInt(proverSourceValue),
      claimValue: BigInt(proverClaimValue),
      secret,
      hashPubKeySecret,
      hashSecret
    };

    // Generate witness
    const w = await circuit.calculateWitness(input, true);

    await circuit.checkConstraints(w);
  });
});
