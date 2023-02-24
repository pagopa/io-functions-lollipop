import * as TE from "fp-ts/TaskEither";

import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";

import { ActivatePubKeyPayload } from "../../generated/definitions/internal/ActivatePubKeyPayload";
import { AssertionTypeEnum } from "../../generated/definitions/internal/AssertionType";

import { ErrorKind } from "../../utils/errors";
import { PopDocumentReader } from "../../utils/readers";
import { AssertionWriter, PopDocumentWriter } from "../../utils/writers";
import { NewLolliPopPubKeys } from "../../model/lollipop_keys";

import { ActivatePubKeyHandler } from "../handler";

import {
  aValidSha256AssertionRef,
  aRetrievedPendingLollipopPubKeySha256,
  aFiscalCode,
  aRetrievedValidLollipopPubKeySha256
} from "../../__mocks__/lollipopPubKey.mock";
import { contextMock } from "../../__mocks__/context.mock";
import { PubKeyStatusEnum } from "../../generated/definitions/internal/PubKeyStatus";
import { AssertionRef } from "../../generated/definitions/internal/AssertionRef";
import { NonNegativeInteger } from "@pagopa/ts-commons/lib/numbers";

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

  it("should return 500 Internal Error when a pop document with status != PENDING is found", async () => {
    popDocumentReaderMock.mockImplementationOnce(assertionRef =>
      TE.of({
        ...aRetrievedValidLollipopPubKeySha256,
        assertionRef: assertionRef,
        id: `${assertionRef}-000000` as NonEmptyString,
        version: 0 as NonNegativeInteger,
        status: PubKeyStatusEnum.REVOKED
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
      detail: "Internal server error: Unexpected status on pop document"
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
