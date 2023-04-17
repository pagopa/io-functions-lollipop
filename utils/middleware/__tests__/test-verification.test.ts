import * as jose from "jose";

import { verifySignatureHeader } from "@mattrglobal/http-signatures";

import { signAlgorithmToVerifierMap } from "../sample-utils/devServer.customVerifier";
import { signAlgorithmToVerifierMap as signAlgorithmToVerifierMapWithDsaEncoding } from "../sample-utils/devServer-withDsaEncoding.customVerifier";
import { customVerify as customVerifyWithoutDsaEncoding } from "../sample-utils/httpSignature-withoutDsaEncoding.verifiers";
import { customVerify } from "../../httpSignature.verifiers";

const url = "https://api-app.io.pagopa.it/first-lollipop/sign";
const body = JSON.stringify({ message: "a valid message payload" });

describe("node-fetch", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("signature with dsaEncoding = ieee-p1363", async () => {
    // TEST Key
    //   pubKeyJwk {
    //      kty: 'EC',
    //      x: 'iC_-UZuFRDFACLQ5ShVCN2VTW6XslbqzUO2QxgNjSms',
    //      y: 'Bj5oKCPqw63f387XqN9R71qH9ZP69jLea4LuKk-wuMc',
    //      crv: 'P-256'
    //    }
    //   privateKeyJwk {
    //      kty: 'EC',
    //      x: 'iC_-UZuFRDFACLQ5ShVCN2VTW6XslbqzUO2QxgNjSms',
    //      y: 'Bj5oKCPqw63f387XqN9R71qH9ZP69jLea4LuKk-wuMc',
    //      crv: 'P-256',
    //      d: 'YddcETpoHqwY1Eid6bRyZgRCTEbE3I5lJUHBJ2Cq-jY'
    //    }
    const encoded =
      "eyJrdHkiOiJFQyIsIngiOiJpQ18tVVp1RlJERkFDTFE1U2hWQ04yVlRXNlhzbGJxelVPMlF4Z05qU21zIiwieSI6IkJqNW9LQ1BxdzYzZjM4N1hxTjlSNzFxSDlaUDY5akxlYTRMdUtrLXd1TWMiLCJjcnYiOiJQLTI1NiJ9";

    const pubKeyJwk = JSON.parse(jose.base64url.decode(encoded).toString());

    const headers = {
      "x-pagopa-lollipop-original-method": "POST",
      "x-pagopa-lollipop-original-url":
        "https://api-app.io.pagopa.it/first-lollipop/sign",
      "content-digest":
        "sha-256=:cpyRqJ1VhoVC+MSs9fq4/4wXs4c46EyEFriskys43Zw=:",
      Signature:
        "sig1=:hISDh6undd5bt34MBE33Kc2Ia6kmjFbu8ex285y4XN7k0wKsdzaCsLk3YWLzKdkXEA6t/vfKVut3OIxG+aszlw==:",
      "Signature-Input":
        'sig1=("x-pagopa-lollipop-original-method" "x-pagopa-lollipop-original-url");created=1681555037;nonce="aNonce";alg="ecdsa-p256-sha256";keyid="sha256-H0YsR4ts39r1dSKVi4-Fy5Bes4R4pjkPK_XWSmdT3YY"'
    };

    const aKeyId = "sha256-H0YsR4ts39r1dSKVi4-Fy5Bes4R4pjkPK_XWSmdT3YY";
    const keyMap = {
      [aKeyId]: { key: pubKeyJwk }
    };

    const verifyParams = {
      httpHeaders: headers,
      method: "POST",
      url,
      body
    };

    const verifiedWithDefault = await verifySignatureHeader({
      ...verifyParams,
      verifier: {
        keyMap
      }
    });
    const verifiedWithCustomVerifier = await verifySignatureHeader({
      ...verifyParams,
      verifier: {
        verify: customVerify(keyMap) as any
      }
    });
    const verifiedDevServerVerifier = await verifySignatureHeader({
      ...verifyParams,
      verifier: {
        verify: signAlgorithmToVerifierMap["ecdsa-p256-sha256"].verify(
          pubKeyJwk
        )
      }
    });
    const verifiedDevServerWithDsaEncodingVerifier = await verifySignatureHeader(
      {
        ...verifyParams,
        verifier: {
          verify: signAlgorithmToVerifierMapWithDsaEncoding[
            "ecdsa-p256-sha256"
          ].verify(pubKeyJwk)
        }
      }
    );
    const verifiedWithoutDsaEncodingVerifier = await verifySignatureHeader({
      ...verifyParams,
      verifier: {
        verify: customVerifyWithoutDsaEncoding(keyMap)
      }
    });

    console.log("verifiedWithDefault ", verifiedWithDefault);
    console.log("verifiedWithCustomVerifier ", verifiedWithCustomVerifier);
    console.log("verifiedDevServerVerifier ", verifiedDevServerVerifier);
    console.log(
      "verifiedDevServerWithDsaEncodingVerifier ",
      verifiedDevServerWithDsaEncodingVerifier
    );
    console.log(
      "verifiedWithoutDsaEncodingVerifier ",
      verifiedWithoutDsaEncodingVerifier
    );

    expect(verifiedWithDefault.unwrapOr({ verified: false })).toMatchObject({
      verified: true
    });
    expect(
      verifiedWithCustomVerifier.unwrapOr({ verified: false })
    ).toMatchObject({
      verified: true
    });
    expect(
      verifiedDevServerVerifier.unwrapOr({ verified: false })
    ).toMatchObject({
      verified: false
    });
    expect(
      verifiedDevServerWithDsaEncodingVerifier.unwrapOr({ verified: false })
    ).toMatchObject({
      verified: true
    });
    expect(
      verifiedWithoutDsaEncodingVerifier.unwrapOr({ verified: false })
    ).toMatchObject({
      verified: false
    });
  });

  it("signature without dsaEncoding = ieee-p1363", async () => {
    const encoded =
      "eyJrdHkiOiJFQyIsInkiOiJNdkVCMENsUHFnTlhrNVhIYm9xN1hZUnE2TnJTQkFTVmZhT2wzWnAxQmJzPSIsImNydiI6IlAtMjU2IiwieCI6InF6YTQzdGtLTnIrYWlTZFdNL0Q1cTdxMElmV3lZVUFIVEhSNng3dFByZEU9In0";

    const pubKeyJwk = JSON.parse(jose.base64url.decode(encoded).toString());

    const headers = {
      "x-pagopa-lollipop-original-url": url,
      "x-pagopa-lollipop-original-method": "POST",
      "content-digest":
        "sha-256=:cpyRqJ1VhoVC+MSs9fq4/4wXs4c46EyEFriskys43Zw=:",
      "signature-input": `sig1=("x-pagopa-lollipop-original-method" "x-pagopa-lollipop-original-url");created=1681473980;nonce="aNonce";alg="ecdsa-p256-sha256";keyid="sha256-HiNolL87UYKQfaKISwIzyWY4swKPUzpaOWJCxaHy89M"`,
      signature: `sig1=:MEUCIFiZHxuLhk2Jlt46E5kbB8hCx7fN7QeeAj2gaSK3Y+WzAiEAtggj3Jwu8RbTGdNmsDix2zymh0gKwKxoPlolL7j6VTg=:`
    };

    const aKeyId = "sha256-HiNolL87UYKQfaKISwIzyWY4swKPUzpaOWJCxaHy89M";
    const keyMap = {
      [aKeyId]: { key: pubKeyJwk }
    };

    const verifyParams = {
      httpHeaders: headers,
      method: "POST",
      url,
      body
    };

    const verifiedWithDefault = await verifySignatureHeader({
      ...verifyParams,
      verifier: {
        keyMap
      }
    });
    const verifiedWithCustomVerifier = await verifySignatureHeader({
      ...verifyParams,
      verifier: {
        verify: customVerify(keyMap) as any
      }
    });
    const verifiedDevServerVerifier = await verifySignatureHeader({
      ...verifyParams,
      verifier: {
        verify: signAlgorithmToVerifierMap["ecdsa-p256-sha256"].verify(
          pubKeyJwk
        )
      }
    });
    const verifiedDevServerWithDsaEncodingVerifier = await verifySignatureHeader(
      {
        ...verifyParams,
        verifier: {
          verify: signAlgorithmToVerifierMapWithDsaEncoding[
            "ecdsa-p256-sha256"
          ].verify(pubKeyJwk)
        }
      }
    );
    const verifiedWithoutDsaEncodingVerifier = await verifySignatureHeader({
      ...verifyParams,
      verifier: {
        verify: customVerifyWithoutDsaEncoding(keyMap)
      }
    });

    console.log("verifiedWithDefault ", verifiedWithDefault);
    console.log("verifiedWithCustomVerifier ", verifiedWithCustomVerifier);
    console.log("verifiedDevServerVerifier ", verifiedDevServerVerifier);
    console.log(
      "verifiedDevServerWithDsaEncodingVerifier ",
      verifiedDevServerWithDsaEncodingVerifier
    );
    console.log(
      "verifiedWithoutDsaEncodingVerifier ",
      verifiedWithoutDsaEncodingVerifier
    );

    expect(verifiedWithDefault.unwrapOr({ verified: false })).toMatchObject({
      verified: false
    });
    expect(
      verifiedWithCustomVerifier.unwrapOr({ verified: false })
    ).toMatchObject({
      verified: false
    });
    expect(
      verifiedDevServerVerifier.unwrapOr({ verified: true })
    ).toMatchObject({
      verified: true
    });
    expect(
      verifiedDevServerWithDsaEncodingVerifier.unwrapOr({ verified: false })
    ).toMatchObject({
      verified: false
    });
    expect(
      verifiedWithoutDsaEncodingVerifier.unwrapOr({ verified: false })
    ).toMatchObject({
      verified: true
    });
  });
});
