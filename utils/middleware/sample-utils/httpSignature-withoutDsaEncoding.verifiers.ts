import * as crypto from "crypto";
import { JsonWebKey } from "crypto";
import { algMap } from "@mattrglobal/http-signatures";

// ----------------------
// Custom Verifiers
// ----------------------

/**
 * Builder for `rsa-pss-sha256` signature verifier.
 * It's based on the`rsa-pss-sha512` one, defined in @mattrglobal/http-signatures library.
 * See https://github.com/mattrglobal/http-signatures/blob/v4.0.1/src/common/cryptoPrimatives.ts
 *
 * @param key the public key
 * @returns a function that takes the data and the signature
 *  and return the comparison between them, based on the algorithm and the public key
 */
export const getVerifyRsaPssSha256WithoutDsaEncoding = (
  key: JsonWebKey
) => async (data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
  const keyObject = crypto.createPublicKey({ format: "jwk", key });
  return crypto
    .createVerify("SHA256")
    .update(data)
    .verify(
      {
        key: keyObject,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING
      },
      signature
    );
};

export const verifyEcdsaSha256WithoutDsaEncoding = (key: JsonWebKey) => async (
  data: Uint8Array,
  signature: Uint8Array
): Promise<boolean> => {
  const keyObject = crypto.createPublicKey({ key, format: "jwk" });
  return crypto
    .createVerify("SHA256")
    .update(data)
    .verify({ key: keyObject }, signature);
};

export type SupportedAlgTypes = keyof typeof extendedAlgMap;

export const extendedAlgMap = {
  ["rsa-pss-sha256"]: {
    verify: getVerifyRsaPssSha256WithoutDsaEncoding
  },
  ["ecdsa-p256-sha256"]: {
    verify: verifyEcdsaSha256WithoutDsaEncoding
  }
};

export const customVerify = (keyMap: {
  readonly [keyid: string]: { readonly key: JsonWebKey };
}) => async (
  signatureParams: { readonly keyid: string; readonly alg: SupportedAlgTypes },
  data: Uint8Array,
  signature: Uint8Array
): Promise<boolean> => {
  if (keyMap[signatureParams.keyid] === undefined) {
    return Promise.resolve(false);
  }
  return extendedAlgMap[signatureParams.alg].verify(
    keyMap[signatureParams.keyid].key
  )(data, signature);
};
