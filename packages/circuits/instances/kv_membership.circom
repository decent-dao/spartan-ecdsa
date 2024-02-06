pragma circom 2.1.2;

include "../lumen/kv_membership.circom";

component main { public[ root, Tx, Ty, Ux, Uy, claimValue, hashPubKeySecret, hashSecret ]} = KVMembership(20);