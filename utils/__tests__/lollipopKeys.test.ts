import { AssertionRef } from "@pagopa/io-functions-commons/dist/generated/definitions/lollipop/AssertionRef";
import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";
import { JwkPubKeyHashAlgorithmEnum } from "../../generated/definitions/internal/JwkPubKeyHashAlgorithm";
import { getAllAssertionsRef } from "../lollipopKeys";
import * as jose from "jose";
import * as E from "fp-ts/Either";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";

const aValidAssertionRef = "sha256-9f86d081884c7d659a2feaa0c55ad015a3bf4f1234" as AssertionRef;
const aValidSha512AssertionRef = "sha512-9f86d081884c7d659a2feaa0c55ad015a3bf4f1234abcdaacabac8734623984f" as AssertionRef;

const anInvalidJwk: JwkPublicKey = {
  alg: "",
  e: "e",
  kty: "RSA",
  n: ""
};

const aValidJwk: JwkPublicKey = {
  kty: "EC",
  crv: "P-256",
  x: "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
  y: "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
};

const masterAlgo = JwkPubKeyHashAlgorithmEnum.sha512;

const toEncodedJwk = (jwk: JwkPublicKey) =>
  jose.base64url.encode(JSON.stringify(jwk)) as NonEmptyString;

describe("getAllAssertionsRef", () => {
  it("GIVEN an invalid pubKey WHEN Jwk decode fails THEN it should return an Error", async () => {
    const result = await getAllAssertionsRef(
      masterAlgo,
      aValidAssertionRef,
      "invalidJWK" as NonEmptyString
    )();
    expect(E.isLeft(result)).toBeTruthy();
    if (E.isLeft(result)) {
      expect(result.left.message).toEqual(
        expect.stringContaining("Cannot decode used jwk")
      );
    }
  });

  it("GIVEN a valid assertionRef and pubKey WHEN master key's thumbprint generation fails THEN it should return an Error", async () => {
    const result = await getAllAssertionsRef(
      masterAlgo,
      aValidAssertionRef,
      toEncodedJwk(anInvalidJwk)
    )();
    expect(E.isLeft(result)).toBeTruthy();
    if (E.isLeft(result)) {
      expect(result.left.message).toEqual(
        expect.stringContaining("Cannot calculate master key jwk's thumbprint")
      );
    }
  });

  it("GIVEN a valid usedAssertionRef and pubKey WHEN masterAlgo match THEN it should return only master assertionRef", async () => {
    const result = await getAllAssertionsRef(
      masterAlgo,
      aValidSha512AssertionRef,
      toEncodedJwk(aValidJwk)
    )();
    expect(E.isRight(result)).toBeTruthy();
    if (E.isRight(result)) {
      expect(result.right).toEqual({ master: aValidSha512AssertionRef });
    }
  });

  it("GIVEN a valid usedAssertionRef and pubKey WHEN masterAlgo does not match THEN it should return master and used assertionsRef", async () => {
    const result = await getAllAssertionsRef(
      masterAlgo,
      aValidAssertionRef,
      toEncodedJwk(aValidJwk)
    )();

    const expectedMasterAssertionThumbprint = await jose.calculateJwkThumbprint(
      aValidJwk,
      masterAlgo
    );
    expect(E.isRight(result)).toBeTruthy();
    if (E.isRight(result)) {
      expect(result.right).toEqual({
        master: `${masterAlgo}-${expectedMasterAssertionThumbprint}`,
        used: aValidAssertionRef
      });
    }
  });
});
