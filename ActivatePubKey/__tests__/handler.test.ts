import * as TE from "fp-ts/lib/TaskEither";
import * as E from "fp-ts/lib/Either";
import {
  AssertionFileName,
  NewLolliPopPubKeys,
  RetrievedLolliPopPubKeys,
  TTL_VALUE_AFTER_UPDATE
} from "../../model/lollipop_keys";
import { FiscalCode, NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { AssertionTypeEnum } from "@pagopa/io-functions-commons/dist/generated/definitions/lollipop/AssertionType";
import { PubKeyStatusEnum } from "../../generated/definitions/internal/PubKeyStatus";
import { NonNegativeInteger } from "@pagopa/ts-commons/lib/numbers";
import { ActivatePubKeyHandler } from "../handler";
import { PopDocumentReader } from "../../utils/readers";
import { AssertionWriter, PopDocumentWriter } from "../../utils/writers";
import { ActivatePubKeyPayload } from "../../generated/definitions/internal/ActivatePubKeyPayload";
import {
  retrievedLollipopKeysToApiActivatedPubKey,
  RetrievedValidPopDocument
} from "../../utils/lollipopKeys";
import { getAllAssertionsRef } from "../../utils/lollipopKeys";
import { JwkPubKeyHashAlgorithmEnum } from "../../generated/definitions/internal/JwkPubKeyHashAlgorithm";
import {
  aCosmosResourceMetadata,
  aRetrievedPendingLollipopPubKeySha256,
  aRetrievedValidLollipopPubKeySha256,
  aValidJwk,
  aValidSha256AssertionRef,
  aValidSha512AssertionRef,
  toEncodedJwk
} from "../../__mocks__/lollipopPubKey.mock";
import { AssertionRef } from "../../generated/definitions/internal/AssertionRef";
import { ErrorKind } from "../../utils/errors";
import { contextMock } from "../../__mocks__/context.mock";

const aFiscalCode = "SPNDNL80A13Y555X" as FiscalCode;

const aValidRetrievedPopDocument: RetrievedLolliPopPubKeys = {
  pubKey: toEncodedJwk(aValidJwk),
  ttl: TTL_VALUE_AFTER_UPDATE,
  assertionType: AssertionTypeEnum.SAML,
  assertionRef: aValidSha256AssertionRef,
  assertionFileName: `${aFiscalCode}-${aValidSha256AssertionRef}` as AssertionFileName,
  status: PubKeyStatusEnum.VALID,
  fiscalCode: aFiscalCode,
  expiredAt: new Date(),
  id: "1" as NonEmptyString,
  version: 1 as NonNegativeInteger,
  ...aCosmosResourceMetadata
};

const aPendingRetrievedPopDocument: RetrievedLolliPopPubKeys = {
  ...aValidRetrievedPopDocument,
  status: PubKeyStatusEnum.PENDING
};

const aValidRetrievedPopDocumentWithMasterAlgo: RetrievedValidPopDocument = {
  ...aValidRetrievedPopDocument,
  assertionRef: aValidSha512AssertionRef,
  assertionFileName: `${aFiscalCode}-${aValidSha512AssertionRef}` as AssertionFileName
};

const aPendingRetrievedPopDocumentWithMasterAlgo = {
  ...aPendingRetrievedPopDocument,
  // to let this document match the master we must change the assertionRef
  // to a sha512 one
  assertionRef: aValidSha512AssertionRef,
  assertionFileName: `${aFiscalCode}-${aValidSha512AssertionRef}`
};

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
      version: 1,
      ttl: TTL_VALUE_AFTER_UPDATE
    }) as ReturnType<PopDocumentWriter>
);
const assertionWriterMock = jest.fn(
  () => TE.of(true) as ReturnType<AssertionWriter>
);

const expiresAtDate = new Date(); // Now

const aValidPayload: ActivatePubKeyPayload = {
  fiscal_code: aFiscalCode,
  assertion: "an assertion" as NonEmptyString,
  assertion_type: AssertionTypeEnum.SAML,
  expired_at: expiresAtDate
};

describe("activatePubKey handler", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should success given valid informations when used algo DIFFERENT FROM master algo", async () => {
    popDocumentReaderMock.mockImplementationOnce(() =>
      TE.right(aPendingRetrievedPopDocument)
    );

    const activatePubKeyHandler = ActivatePubKeyHandler(
      popDocumentReaderMock,
      popDocumentWriterMock,
      assertionWriterMock
    );

    const aValidActivatePubKeyPayload: ActivatePubKeyPayload = {
      fiscal_code: aFiscalCode,
      expired_at: expiresAtDate,
      assertion_type: AssertionTypeEnum.SAML,
      assertion: "" as NonEmptyString
    };

    const assertionRefsResult = await getAllAssertionsRef(
      JwkPubKeyHashAlgorithmEnum.sha512,
      JwkPubKeyHashAlgorithmEnum.sha256,
      aValidJwk
    )();

    if (E.isLeft(assertionRefsResult)) fail();

    const res = await activatePubKeyHandler(
      contextMock,
      aValidSha256AssertionRef,
      aValidActivatePubKeyPayload
    );

    expect(popDocumentReaderMock).toHaveBeenCalledTimes(1);
    expect(popDocumentReaderMock).toHaveBeenCalledWith(
      aValidSha256AssertionRef
    );
    expect(assertionWriterMock).toHaveBeenCalledTimes(1);
    expect(assertionWriterMock).toHaveBeenCalledWith(
      `${aValidActivatePubKeyPayload.fiscal_code}-${aValidSha256AssertionRef}`,
      ""
    );
    expect(popDocumentWriterMock).toHaveBeenCalledTimes(2);
    expect(popDocumentWriterMock).toHaveBeenNthCalledWith(1, {
      pubKey: aPendingRetrievedPopDocument.pubKey,
      // the assertion Ref for masterKey is created by the getAllAssertionRefs method
      assertionRef: assertionRefsResult.right.master,
      assertionFileName: `${aFiscalCode}-${aValidSha256AssertionRef}`,
      status: PubKeyStatusEnum.VALID,
      assertionType: aValidActivatePubKeyPayload.assertion_type,
      fiscalCode: aValidActivatePubKeyPayload.fiscal_code,
      expiredAt: aValidActivatePubKeyPayload.expired_at
    });
    expect(popDocumentWriterMock).toHaveBeenNthCalledWith(2, {
      pubKey: aPendingRetrievedPopDocument.pubKey,
      assertionRef: aValidSha256AssertionRef,
      assertionFileName: `${aFiscalCode}-${aValidSha256AssertionRef}`,
      status: PubKeyStatusEnum.VALID,
      assertionType: aValidActivatePubKeyPayload.assertion_type,
      fiscalCode: aValidActivatePubKeyPayload.fiscal_code,
      expiredAt: aValidActivatePubKeyPayload.expired_at
    });

    expect(res.kind).toBe("IResponseSuccessJson");
    expect(res).toMatchObject({
      kind: "IResponseSuccessJson",
      value: retrievedLollipopKeysToApiActivatedPubKey(
        aValidRetrievedPopDocument
      )
    });
  });

  it("should success given valid informations when used algo EQUALS TO master algo", async () => {
    popDocumentReaderMock.mockImplementationOnce(() =>
      TE.right(aPendingRetrievedPopDocumentWithMasterAlgo)
    );

    const activatePubKeyHandler = ActivatePubKeyHandler(
      popDocumentReaderMock,
      popDocumentWriterMock,
      assertionWriterMock
    );

    const aValidActivatePubKeyPayload: ActivatePubKeyPayload = {
      fiscal_code: aFiscalCode,
      expired_at: expiresAtDate,
      assertion_type: AssertionTypeEnum.SAML,
      assertion: "" as NonEmptyString
    };

    const assertionRefsResult = await getAllAssertionsRef(
      JwkPubKeyHashAlgorithmEnum.sha512,
      JwkPubKeyHashAlgorithmEnum.sha512,
      aValidJwk
    )();

    if (E.isLeft(assertionRefsResult)) fail();

    const res = await activatePubKeyHandler(
      contextMock,
      aValidSha512AssertionRef,
      aValidActivatePubKeyPayload
    );

    expect(popDocumentReaderMock).toHaveBeenCalledTimes(1);
    expect(popDocumentReaderMock).toHaveBeenCalledWith(
      aValidSha512AssertionRef
    );
    expect(assertionWriterMock).toHaveBeenCalledTimes(1);
    expect(assertionWriterMock).toHaveBeenCalledWith(
      `${aValidActivatePubKeyPayload.fiscal_code}-${aValidSha512AssertionRef}`,
      ""
    );
    expect(popDocumentWriterMock).toHaveBeenCalledTimes(1);
    expect(popDocumentWriterMock).toHaveBeenCalledWith({
      pubKey: aPendingRetrievedPopDocument.pubKey,
      // the assertion Ref for masterKey is created by the getAllAssertionRefs method
      assertionRef: assertionRefsResult.right.master,
      assertionFileName: `${aFiscalCode}-${aValidSha512AssertionRef}`,
      status: PubKeyStatusEnum.VALID,
      assertionType: aValidActivatePubKeyPayload.assertion_type,
      fiscalCode: aValidActivatePubKeyPayload.fiscal_code,
      expiredAt: aValidActivatePubKeyPayload.expired_at
    });

    expect(res.kind).toBe("IResponseSuccessJson");
    expect(res).toMatchObject({
      kind: "IResponseSuccessJson",
      value: retrievedLollipopKeysToApiActivatedPubKey(
        aValidRetrievedPopDocumentWithMasterAlgo
      )
    });
  });
});

describe("ActivatePubKey - Errors", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return 500 Error when assertionRef doen not exists", async () => {
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
      kind: "IResponseErrorInternal",
      detail:
        "Internal server error: Error while reading pop document: NotFound"
    });

    expect(popDocumentReaderMock).toHaveBeenCalledWith(
      aValidSha256AssertionRef
    );
    expect(assertionWriterMock).not.toHaveBeenCalled();
    expect(popDocumentWriterMock).not.toHaveBeenCalled();
  });

  it("should return 403 Forbidden Not Authorized when a pop document with status DIFFERENT FROM PENDING is found", async () => {
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

    expect(res).toMatchObject(
      expect.objectContaining({
        kind: "IResponseErrorForbiddenNotAuthorized"
      })
    );

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
      detail:
        "Internal server error: Error while reading pop document: Internal"
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
