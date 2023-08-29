pragma circom 2.1.2;
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../eff_ecdsa_membership/tree.circom";
include "../eff_ecdsa_membership/to_address/zk-identity/eth.circom";
include "../eff_ecdsa_membership/eff_ecdsa.circom";
include "../poseidon/poseidon.circom";

template KVMembership(nLevels) {
    
    // private inputs
    signal input secret;
    signal input s;
    signal input sourceValue;
    signal input pathIndices[nLevels];
    signal input siblings[nLevels];
    
    // public inputs
    signal input root;
    signal input hashPubKeySecret; // hash(public_key, secret)
    signal input hashSecret; // hash(secret)
    signal input claimValue;
    signal input Tx;
    signal input Ty;
    signal input Ux;
    signal input Uy;

    // Compute public key from EfficientECDSA
    component ecdsa = EfficientECDSA();
    ecdsa.s <== s;
    ecdsa.Tx <== Tx;
    ecdsa.Ty <== Ty;
    ecdsa.Ux <== Ux;
    ecdsa.Uy <== Uy;

    /** 
        * Nullifier check              
        * 1. hash(public_key_x, secret)
        * 2. hash(secret) 
        * 3. compare hashed private inputs to public inputs
     */
    
     // Hashing the public key X and Y coordinates
    component hPubKeyXY = Poseidon();
    hPubKeyXY.inputs[0] <== ecdsa.pubKeyX; // Use the public key X coordinate
    hPubKeyXY.inputs[1] <== ecdsa.pubKeyY; // Use the public key Y coordinate

    component hPubKeySecret = Poseidon();
    hPubKeySecret.inputs[0] <== hPubKeyXY.out;
    hPubKeySecret.inputs[1] <== secret;

    component hSecret = Poseidon();
    hSecret.inputs[0] <== secret;
    hSecret.inputs[1] <== 0;

    hashSecret === hSecret.out;
    hashPubKeySecret === hPubKeySecret.out;


    /** 
        * Merkle proof check
        * 1. combine and convert pubkey parts to 256 bits
        * 2. convert pubkey to address
        * 3. hash address + sourceValue
        * 4. verify merkle proof
    */
    
    component pubKeyXBits = Num2Bits(256);
    pubKeyXBits.in <== ecdsa.pubKeyX;

    component pubKeyYBits = Num2Bits(256);
    pubKeyYBits.in <== ecdsa.pubKeyY;

    component pubToAddr = PubkeyToAddress();

    for (var i = 0; i < 256; i++) {
        pubToAddr.pubkeyBits[i] <== pubKeyYBits.out[i];
        pubToAddr.pubkeyBits[i + 256] <== pubKeyXBits.out[i];
    }


    // Hash 0x...edfg + balance
    component kvHash = Poseidon();
    kvHash.inputs[0] <== pubToAddr.address;
    kvHash.inputs[1] <== sourceValue;


    component merkleProof = MerkleTreeInclusionProof(nLevels);
    merkleProof.leaf <== kvHash.out;

    for (var i = 0; i < nLevels; i++) {
        merkleProof.pathIndices[i] <== pathIndices[i];
        merkleProof.siblings[i] <== siblings[i];
    }

    // verify root hash
    root === merkleProof.root;

    // Verify statement value validity
    // 0 => sourceValue can be higher than claimValue 
    // Prevent overflow of comparator range
    component sourceInRange = Num2Bits(252);
    sourceInRange.in <== sourceValue;
    component claimInRange = Num2Bits(252);
    claimInRange.in <== claimValue;
    // 0 <= statementValue <= sourceValue
    component leq = LessEqThan(252);
    leq.in[0] <== claimValue;
    leq.in[1] <== sourceValue;
    leq.out === 1;
}