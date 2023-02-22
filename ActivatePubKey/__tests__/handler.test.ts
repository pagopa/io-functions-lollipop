import * as jose from "jose";

import * as TE from "fp-ts/TaskEither";

import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";

import { ActivatePubKeyPayload } from "../../generated/definitions/internal/ActivatePubKeyPayload";
import { AssertionTypeEnum } from "../../generated/definitions/internal/AssertionType";

import { ErrorKind } from "../../utils/domain_errors";
import { PopDocumentReader } from "../../utils/readers";
import { AssertionWriter, PopDocumentWriter } from "../../utils/writers";
import { NewLolliPopPubKeys } from "../../model/lollipop_keys";

import { ActivatePubKeyHandler } from "../handler";

import {
  aValidSha256AssertionRef,
  aRetrievedPendingLollipopPubKeySha256,
  aFiscalCode,
  toEncodedJwk,
  aValidJwk,
  aValidSha512AssertionRef,
  aRetrievedPendingLollipopPubKeySha512
} from "../../__mocks__/lollipopPubKey.mock";
import { contextMock } from "../../__mocks__/context.mock";
import { ResponseSuccessJson } from "@pagopa/ts-commons/lib/responses";
import { Timestamp } from "../../generated/definitions/internal/Timestamp";
import { PubKeyStatusEnum } from "../../generated/definitions/internal/PubKeyStatus";
import { AssertionRef } from "../../generated/definitions/internal/AssertionRef";

const popDocumentReaderMock = jest.fn(
  (assertionRef: AssertionRef) =>
    TE.of({
      ...aRetrievedPendingLollipopPubKeySha256,
      assertionRef: assertionRef,
      id: `${assertionRef}-000000`,
      version: 0
    }) as ReturnType<PopDocumentReader>
);

const popDocumentWriterMock = jest.fn(
  (item: NewLolliPopPubKeys) =>
    TE.of({
      ...aRetrievedPendingLollipopPubKeySha256,
      ...item,
      id: `${item.assertionRef}-000001`,
      version: 1
    }) as ReturnType<PopDocumentWriter>
);
const assertionWriterMock = jest.fn(
  () => TE.of(true) as ReturnType<AssertionWriter>
);

const masterAlgo = "sha512";

var expiresAtDate = new Date(); // Now
expiresAtDate.setDate(expiresAtDate.getDate() + 30); // Set now + 30 days as the new date

const aValidPayload: ActivatePubKeyPayload = {
  fiscal_code: aFiscalCode,
  assertion: "an assertion" as NonEmptyString,
  assertion_type: AssertionTypeEnum.SAML,
  expires_at: expiresAtDate
};

describe("ActivatePubKey - Success", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return the ActivatedPubKey object when assertion_ref is sha256", async () => {
    const handler = ActivatePubKeyHandler(
      popDocumentReaderMock,
      popDocumentWriterMock,
      assertionWriterMock
    );

    const res = await handler(
      contextMock,
      aValidSha256AssertionRef,
      aValidPayload
    );

    const expectedResult = {
      assertionFileName: `${aFiscalCode}-${aValidSha256AssertionRef}`,
      assertionRef: aValidSha256AssertionRef,
      assertionType: AssertionTypeEnum.SAML,
      expiredAt: expiresAtDate,
      fiscalCode: aFiscalCode,
      pubKey: aRetrievedPendingLollipopPubKeySha256.pubKey,
      status: PubKeyStatusEnum.VALID
    };

    const expectedSha512Thumbprint = await jose.calculateJwkThumbprint(
      aValidJwk,
      masterAlgo
    );

    expect(res).toMatchObject({
      kind: "IResponseSuccessJson",
      value: {
        assertion_file_name: expectedResult.assertionFileName,
        assertion_ref: expectedResult.assertionRef,
        assertion_type: expectedResult.assertionType,
        expires_at: expectedResult.expiredAt,
        fiscal_code: expectedResult.fiscalCode,
        pub_key: expectedResult.pubKey,
        status: expectedResult.status,
        version: 1
      }
    });

    expect(popDocumentReaderMock).toHaveBeenCalledWith(
      aValidSha256AssertionRef
    );
    expect(assertionWriterMock).toHaveBeenCalledWith(
      expectedResult.assertionFileName,
      aValidPayload.assertion
    );
    expect(popDocumentWriterMock).toHaveBeenCalledTimes(2);
    expect(popDocumentWriterMock).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        ...expectedResult,
        assertionRef: `sha512-${expectedSha512Thumbprint}`
      })
    );
    expect(popDocumentWriterMock).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        ...expectedResult
      })
    );
  });

  it("should return the ActivatedPubKey object when assertion_ref is sha512", async () => {
    const handler = ActivatePubKeyHandler(
      popDocumentReaderMock,
      popDocumentWriterMock,
      assertionWriterMock
    );

    const res = await handler(
      contextMock,
      aValidSha512AssertionRef,
      aValidPayload
    );

    const expectedResult = {
      assertionFileName: `${aFiscalCode}-${aValidSha512AssertionRef}`,
      assertionRef: aValidSha512AssertionRef,
      assertionType: AssertionTypeEnum.SAML,
      expiredAt: expiresAtDate,
      fiscalCode: aFiscalCode,
      pubKey: aRetrievedPendingLollipopPubKeySha512.pubKey,
      status: PubKeyStatusEnum.VALID
    };

    expect(res).toMatchObject({
      kind: "IResponseSuccessJson",
      value: {
        assertion_file_name: expectedResult.assertionFileName,
        assertion_ref: expectedResult.assertionRef,
        assertion_type: expectedResult.assertionType,
        expires_at: expectedResult.expiredAt,
        fiscal_code: expectedResult.fiscalCode,
        pub_key: expectedResult.pubKey,
        status: expectedResult.status,
        version: 1
      }
    });

    expect(popDocumentReaderMock).toHaveBeenCalledWith(
      aValidSha512AssertionRef
    );
    expect(assertionWriterMock).toHaveBeenCalledWith(
      expectedResult.assertionFileName,
      aValidPayload.assertion
    );
    expect(popDocumentWriterMock).toHaveBeenCalledTimes(1);

    expect(popDocumentWriterMock).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        ...expectedResult
      })
    );
  });
});

describe("ActivatePubKey - Errors", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return 404 NotFound when assertionRef doen not exists", async () => {
    popDocumentReaderMock.mockImplementationOnce(() =>
      TE.left({ kind: ErrorKind.NotFound })
    );

    const handler = ActivatePubKeyHandler(
      popDocumentReaderMock,
      popDocumentWriterMock,
      assertionWriterMock
    );

    const res = await handler(
      contextMock,
      aValidSha256AssertionRef,
      aValidPayload
    );

    expect(res).toMatchObject({
      kind: "IResponseErrorNotFound",
      detail: "NotFound: Could not find requested resource"
    });

    expect(popDocumentReaderMock).toHaveBeenCalledWith(
      aValidSha256AssertionRef
    );
    expect(assertionWriterMock).not.toHaveBeenCalled();
    expect(popDocumentWriterMock).not.toHaveBeenCalled();
  });

  it("should return 500 Internal Error when an error occurred reading document", async () => {
    popDocumentReaderMock.mockImplementationOnce(() =>
      TE.left({ kind: ErrorKind.Internal, detail: "an Error" })
    );

    const handler = ActivatePubKeyHandler(
      popDocumentReaderMock,
      popDocumentWriterMock,
      assertionWriterMock
    );

    const res = await handler(
      contextMock,
      aValidSha256AssertionRef,
      aValidPayload
    );

    expect(res).toMatchObject({
      kind: "IResponseErrorInternal",
      detail: "Internal server error: an Error"
    });

    expect(popDocumentReaderMock).toHaveBeenCalledWith(
      aValidSha256AssertionRef
    );
    expect(assertionWriterMock).not.toHaveBeenCalled();
    expect(popDocumentWriterMock).not.toHaveBeenCalled();
  });

  it("should return 500 Internal Error when an error occurred writing assertion into storage", async () => {
    assertionWriterMock.mockImplementationOnce(() =>
      TE.left({ kind: ErrorKind.Internal, detail: "an Error on storage" })
    );

    const handler = ActivatePubKeyHandler(
      popDocumentReaderMock,
      popDocumentWriterMock,
      assertionWriterMock
    );

    const res = await handler(
      contextMock,
      aValidSha256AssertionRef,
      aValidPayload
    );

    expect(res).toMatchObject({
      kind: "IResponseErrorInternal",
      detail: "Internal server error: an Error on storage"
    });

    const expectedResult = {
      assertionFileName: `${aFiscalCode}-${aValidSha256AssertionRef}`
    };

    expect(popDocumentReaderMock).toHaveBeenCalledWith(
      aValidSha256AssertionRef
    );
    expect(assertionWriterMock).toHaveBeenCalledWith(
      expectedResult.assertionFileName,
      aValidPayload.assertion
    );
    expect(popDocumentWriterMock).not.toHaveBeenCalled();
  });

  it("should return 500 Internal Error when an error occurred storing master key", async () => {
    popDocumentWriterMock.mockImplementationOnce(() =>
      TE.left({ kind: ErrorKind.Internal, detail: "an Error on cosmos update" })
    );

    const handler = ActivatePubKeyHandler(
      popDocumentReaderMock,
      popDocumentWriterMock,
      assertionWriterMock
    );

    const res = await handler(
      contextMock,
      aValidSha256AssertionRef,
      aValidPayload
    );

    expect(res).toMatchObject({
      kind: "IResponseErrorInternal",
      detail: "Internal server error: an Error on cosmos update"
    });

    const expectedResult = {
      assertionFileName: `${aFiscalCode}-${aValidSha256AssertionRef}`
    };

    expect(popDocumentReaderMock).toHaveBeenCalledWith(
      aValidSha256AssertionRef
    );
    expect(assertionWriterMock).toHaveBeenCalledWith(
      expectedResult.assertionFileName,
      aValidPayload.assertion
    );
    expect(popDocumentWriterMock).toHaveBeenCalledTimes(1);
  });

  it("should return 500 Internal Error when an error occurred storing used key", async () => {
    popDocumentWriterMock
      // First insert OK
      .mockImplementationOnce(
        (item: NewLolliPopPubKeys) =>
          TE.of({
            ...aRetrievedPendingLollipopPubKeySha256,
            ...item,
            id: `${item.assertionRef}-000001`,
            version: 1
          }) as ReturnType<PopDocumentWriter>
      )
      // Second insert KO
      .mockImplementationOnce(() =>
        TE.left({
          kind: ErrorKind.Internal,
          detail: "an Error on cosmos update"
        })
      );

    const handler = ActivatePubKeyHandler(
      popDocumentReaderMock,
      popDocumentWriterMock,
      assertionWriterMock
    );

    const res = await handler(
      contextMock,
      aValidSha256AssertionRef,
      aValidPayload
    );

    expect(res).toMatchObject({
      kind: "IResponseErrorInternal",
      detail: "Internal server error: an Error on cosmos update"
    });

    const expectedResult = {
      assertionFileName: `${aFiscalCode}-${aValidSha256AssertionRef}`
    };

    expect(popDocumentReaderMock).toHaveBeenCalledWith(
      aValidSha256AssertionRef
    );
    expect(assertionWriterMock).toHaveBeenCalledWith(
      expectedResult.assertionFileName,
      aValidPayload.assertion
    );
    expect(popDocumentWriterMock).toHaveBeenCalledTimes(2);
  });
});
