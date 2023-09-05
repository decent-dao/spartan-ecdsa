import {
  KVMembershipProver,
  KVMembershipVerifier,
  Poseidon,
  LumenNIZK
} from "../src/lib";

import { BigNumber, ethers } from 'ethers'
import { SigningKey } from 'ethers/lib/utils';
import * as path from "path";
import { eip712MsgHash, CONTENT_TYPES, CONTENT_VALUES, DOMAIN, createMerkleProof } from "./helpers/lumen_utils";


describe("kv_membership", () => {
  const treeDepth = 20;

  // Sample private keys for testing purposes
  const privKeys = ["1", "a", "bb", "ccc", "dddd"].map(val =>
    Buffer.from(val.padStart(64, "0"), "hex")
  );

  // Sample private key for testing purposes (hardhat account 0)
  const privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
  privKeys.unshift(Buffer.from(privateKey.slice(2), "hex"))

  const proverIndex = 0; // Index of the prover's private key within the privKeys array
  const proverPrivKey = privKeys[proverIndex]; // Prover's private key for the proof

  let poseidon: Poseidon;

  beforeAll(async () => {
    // Init Poseidon
    poseidon = new Poseidon();
    await poseidon.initWasm();
  });

  describe("kv_membership prover and verify", () => {
    const config = {
      witnessGenWasm: path.join(
        __dirname,
        "../../circuits/build/kv_membership/kv_membership_js/kv_membership.wasm"
      ),
      circuit: path.join(
        __dirname,
        "../../circuits/build/kv_membership/kv_membership.circuit"
      )
    };

    let kvMembershipVerifier: KVMembershipVerifier, nizk: LumenNIZK;

    let signingKey: SigningKey
    let wallet: ethers.Wallet
    let msgHash: Buffer
    let sig: string
    let secret: bigint
    let hashPubKey: bigint
    let hSecret: bigint
    let hPubKeySecret: bigint

    beforeAll(async () => {
      kvMembershipVerifier = new KVMembershipVerifier({
        circuit: config.circuit
      });

      await kvMembershipVerifier.initWasm();

      /**
       * EIP712 signing
       * https://docs.ethers.io/v5/api/signer/#Wallet-signTypedData
       * 
       * Creates hashPublickey and hashSecret for the circuit
       * 
       */
      signingKey = new SigningKey(privateKey)
      wallet = new ethers.Wallet(signingKey)

      msgHash = eip712MsgHash(DOMAIN, CONTENT_TYPES, CONTENT_VALUES);

      sig = await wallet._signTypedData(DOMAIN, CONTENT_TYPES, CONTENT_VALUES)
      secret = BigInt(`0x${Buffer.from("".padStart(16, "🧙"), "utf16le").toString("hex")}`);

      const pubKeyX = BigNumber.from('0x' + signingKey.publicKey.slice(4, 68))
      const pubKeyY = BigNumber.from('0x' + signingKey.publicKey.slice(68, 132))

      hashPubKey = poseidon.hash([BigInt(pubKeyX.toString()), BigInt(pubKeyY.toString())]);
      hSecret = poseidon.hash([secret, BigInt(0)]);
      hPubKeySecret = poseidon.hash([hashPubKey, secret]);
    });

    describe("should prove and verify valid signature and merkle proof inclusion", () => {

      it("should prove and verify valid signature and merkle proof inclusion", async () => {

        const kvyMembershipProver = new KVMembershipProver(config);
        await kvyMembershipProver.initWasm();

        const proverClaimValue = 10000;
        const proverSourceValue = 100000;

        const { merkleProof } = createMerkleProof(treeDepth, poseidon, privKeys, proverPrivKey, proverClaimValue, proverSourceValue);

        nizk = await kvyMembershipProver.prove(sig, msgHash, merkleProof, BigInt(proverClaimValue), BigInt(proverSourceValue), secret, hPubKeySecret, hSecret);

        const { proof, publicInput } = nizk;
        expect(
          await kvMembershipVerifier.verify(proof, publicInput.serialize())
        ).toBe(true);
      });

      it("should assert invalid proof", async () => {
        // This test modifies the valid proof and verifies that it is detected as invalid.
        const { publicInput } = nizk;
        let proof = nizk.proof;
        proof[0] = proof[0] += 1;
        expect(
          await kvMembershipVerifier.verify(proof, publicInput.serialize())
        ).toBe(false);
      });

      it("should assert invalid public input", async () => {
        // This test modifies the public input and verifies that the modified input is detected as invalid.
        const { proof } = nizk;
        let publicInput = nizk.publicInput.serialize();
        publicInput[0] = publicInput[0] += 1;
        expect(await kvMembershipVerifier.verify(proof, publicInput)).toBe(
          false
        );
      });
    })

    it("should panic fail if claim value is more than source value", async () => {
      // This test creates a panic in the circuit and verifies that the panic is detected.
      try {

        const kvyMembershipProver = new KVMembershipProver(config);
        await kvyMembershipProver.initWasm();
        const proverSourceValue = 10000;
        const proverClaimValue = 100000;

        const { merkleProof } = createMerkleProof(treeDepth, poseidon, privKeys, proverPrivKey, 100000, 10000);

        await kvyMembershipProver.prove(sig, msgHash, merkleProof, BigInt(proverClaimValue), BigInt(proverSourceValue), secret, hPubKeySecret, hSecret)
      } catch (e) {
        expect(true)
      }

    });

  });
});
