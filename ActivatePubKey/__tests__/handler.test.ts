import * as TE from "fp-ts/lib/TaskEither";
import * as O from "fp-ts/lib/Option";
import * as E from "fp-ts/lib/Either";
import {
  AssertionFileName,
  LolliPOPKeysModel,
  NewLolliPopPubKeys,
  RetrievedLolliPopPubKeys,
  TTL_VALUE_AFTER_UPDATE
} from "../../model/lollipop_keys";
import { FiscalCode, NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { AssertionTypeEnum } from "@pagopa/io-functions-commons/dist/generated/definitions/lollipop/AssertionType";
import { PubKeyStatusEnum } from "../../generated/definitions/internal/PubKeyStatus";
import { NonNegativeInteger } from "@pagopa/ts-commons/lib/numbers";
import { ActivatePubKeyHandler } from "../handler";
import { BlobService } from "azure-storage";
import { getPopDocumentReader, PopDocumentReader } from "../../utils/readers";
import {
  AssertionWriter,
  getAssertionWriter,
  getPopDocumentWriter,
  PopDocumentWriter
} from "../../utils/writers";
import { ActivatePubKeyPayload } from "../../generated/definitions/internal/ActivatePubKeyPayload";
import {
  retrievedLollipopKeysToApiActivatedPubKey,
  RetrievedValidPopDocument
} from "../../utils/lollipopKeys";
import * as fn_commons from "@pagopa/io-functions-commons/dist/src/utils/azure_storage";
import { getAllAssertionsRef } from "../../utils/lollipopKeys";
import { JwkPubKeyHashAlgorithmEnum } from "../../generated/definitions/internal/JwkPubKeyHashAlgorithm";
import {
  aRetrievedPendingLollipopPubKeySha256,
  aRetrievedValidLollipopPubKeySha256,
  aValidJwk,
  aValidSha256AssertionRef,
  aValidSha512AssertionRef,
  toEncodedJwk
} from "../../__mocks__/lollipopPubKey.mock";
import { blobServiceMock } from "../../__mocks__/blobService.mock";
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
  version: 0 as NonNegativeInteger,
  _etag: "",
  _rid: "",
  _self: "",
  _ts: 0
};

const aPendingRetrievedPopDocument: RetrievedLolliPopPubKeys = {
  ...aValidRetrievedPopDocument,
  status: PubKeyStatusEnum.PENDING
};

const aValidRetrievedPopDocumentWithMasterAlgo = {
  ...aValidRetrievedPopDocument,
  assertionRef: aValidSha512AssertionRef,
  assertionFileName: `${aFiscalCode}-${aValidSha512AssertionRef}`
} as RetrievedValidPopDocument;

const aPendingRetrievedPopDocumentWithMasterAlgo = {
  ...aPendingRetrievedPopDocument,
  // to let this document match the master we must change the assertionRef
  // to a sha512 one
  assertionRef: aValidSha512AssertionRef,
  assertionFileName: `${aFiscalCode}-${aValidSha512AssertionRef}`
};

const upsertBlobFromTextMock = jest.spyOn(fn_commons, "upsertBlobFromText");

const findLastVersionByModelIdMock = jest
  .fn()
  .mockImplementation(() => TE.of(O.some({})));

const upsertMock = jest.fn().mockImplementation(() => TE.of({}));

const lollipopPubKeysModelMock = ({
  findLastVersionByModelId: findLastVersionByModelIdMock,
  upsert: upsertMock
} as unknown) as LolliPOPKeysModel;

const LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME = "assertions" as NonEmptyString;

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

var expiresAtDate = new Date(); // Now
expiresAtDate.setDate(expiresAtDate.getDate() + 30); // Set now + 30 days as the new date

const aValidPayload: ActivatePubKeyPayload = {
  fiscal_code: aFiscalCode,
  assertion: "an assertion" as NonEmptyString,
  assertion_type: AssertionTypeEnum.SAML,
  expires_at: expiresAtDate
};

describe("activatePubKey handler", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should success given valid informations when used algo != master algo", async () => {
    upsertBlobFromTextMock.mockImplementationOnce(() =>
      Promise.resolve(
        E.right(O.fromNullable({ name: "blob" } as BlobService.BlobResult))
      )
    );

    findLastVersionByModelIdMock.mockImplementationOnce(() =>
      TE.right(O.some(aPendingRetrievedPopDocument))
    );

    upsertMock.mockImplementationOnce(() => {
      return TE.right(aValidRetrievedPopDocument);
    });

    upsertMock.mockImplementationOnce(() => {
      return TE.right(aValidRetrievedPopDocument);
    });

    const activatePubKeyHandler = ActivatePubKeyHandler(
      getPopDocumentReader(lollipopPubKeysModelMock),
      getPopDocumentWriter(lollipopPubKeysModelMock),
      getAssertionWriter(
        blobServiceMock,
        LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME
      )
    );

    const aValidActivatePubKeyPayload: ActivatePubKeyPayload = {
      fiscal_code: aFiscalCode,
      expires_at: new Date(),
      assertion_type: AssertionTypeEnum.SAML,
      assertion: "" as NonEmptyString
    };

    const assertionRefsResult = await getAllAssertionsRef(
      JwkPubKeyHashAlgorithmEnum.sha512,
      JwkPubKeyHashAlgorithmEnum.sha256,
      aValidJwk
    )();

    if (assertionRefsResult._tag === "Left") fail();

    const res = await activatePubKeyHandler(
      contextMock,
      aValidSha256AssertionRef,
      aValidActivatePubKeyPayload
    );

    expect(findLastVersionByModelIdMock).toHaveBeenCalledTimes(1);
    expect(findLastVersionByModelIdMock).toHaveBeenCalledWith([
      aValidSha256AssertionRef
    ]);
    expect(upsertBlobFromTextMock).toHaveBeenCalledTimes(1);
    expect(upsertBlobFromTextMock).toHaveBeenCalledWith(
      blobServiceMock,
      LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME,
      `${aValidActivatePubKeyPayload.fiscal_code}-${aValidSha256AssertionRef}`,
      ""
    );
    expect(upsertMock).toHaveBeenCalledTimes(2);
    expect(upsertMock).toHaveBeenNthCalledWith(1, {
      pubKey: aPendingRetrievedPopDocument.pubKey,
      // the assertion Ref for masterKey is created by the getAllAssertionRefs method
      assertionRef: assertionRefsResult.right.master,
      assertionFileName: `${aFiscalCode}-${aValidSha256AssertionRef}`,
      status: PubKeyStatusEnum.VALID,
      assertionType: aValidActivatePubKeyPayload.assertion_type,
      fiscalCode: aValidActivatePubKeyPayload.fiscal_code,
      expiredAt: aValidActivatePubKeyPayload.expires_at
    });
    expect(upsertMock).toHaveBeenNthCalledWith(2, {
      pubKey: aPendingRetrievedPopDocument.pubKey,
      assertionRef: aValidSha256AssertionRef,
      assertionFileName: `${aFiscalCode}-${aValidSha256AssertionRef}`,
      status: PubKeyStatusEnum.VALID,
      assertionType: aValidActivatePubKeyPayload.assertion_type,
      fiscalCode: aValidActivatePubKeyPayload.fiscal_code,
      expiredAt: aValidActivatePubKeyPayload.expires_at
    });

    expect(res.kind).toBe("IResponseSuccessJson");
    expect(res).toMatchObject({
      kind: "IResponseSuccessJson",
      value: retrievedLollipopKeysToApiActivatedPubKey(
        aValidRetrievedPopDocument
      )
    });
  });

  it("should success given valid informations when used algo == master algo", async () => {
    upsertBlobFromTextMock.mockImplementationOnce(() =>
      Promise.resolve(
        E.right(O.fromNullable({ name: "blob" } as BlobService.BlobResult))
      )
    );

    findLastVersionByModelIdMock.mockImplementationOnce(() =>
      TE.right(O.some(aPendingRetrievedPopDocumentWithMasterAlgo))
    );

    upsertMock.mockImplementationOnce(() => {
      return TE.right(aValidRetrievedPopDocumentWithMasterAlgo);
    });

    const activatePubKeyHandler = ActivatePubKeyHandler(
      getPopDocumentReader(lollipopPubKeysModelMock),
      getPopDocumentWriter(lollipopPubKeysModelMock),
      getAssertionWriter(
        blobServiceMock,
        LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME
      )
    );

    const aValidActivatePubKeyPayload: ActivatePubKeyPayload = {
      fiscal_code: aFiscalCode,
      expires_at: new Date(),
      assertion_type: AssertionTypeEnum.SAML,
      assertion: "" as NonEmptyString
    };

    const assertionRefsResult = await getAllAssertionsRef(
      JwkPubKeyHashAlgorithmEnum.sha512,
      JwkPubKeyHashAlgorithmEnum.sha512,
      aValidJwk
    )();

    if (assertionRefsResult._tag === "Left") fail();

    const res = await activatePubKeyHandler(
      contextMock,
      aValidSha512AssertionRef,
      aValidActivatePubKeyPayload
    );

    expect(findLastVersionByModelIdMock).toHaveBeenCalledTimes(1);
    expect(findLastVersionByModelIdMock).toHaveBeenCalledWith([
      aValidSha512AssertionRef
    ]);
    expect(upsertBlobFromTextMock).toHaveBeenCalledTimes(1);
    expect(upsertBlobFromTextMock).toHaveBeenCalledWith(
      blobServiceMock,
      LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME,
      `${aValidActivatePubKeyPayload.fiscal_code}-${aValidSha512AssertionRef}`,
      ""
    );
    expect(upsertMock).toHaveBeenCalledTimes(1);
    expect(upsertMock).toHaveBeenCalledWith({
      pubKey: aPendingRetrievedPopDocument.pubKey,
      // the assertion Ref for masterKey is created by the getAllAssertionRefs method
      assertionRef: assertionRefsResult.right.master,
      assertionFileName: `${aFiscalCode}-${aValidSha512AssertionRef}`,
      status: PubKeyStatusEnum.VALID,
      assertionType: aValidActivatePubKeyPayload.assertion_type,
      fiscalCode: aValidActivatePubKeyPayload.fiscal_code,
      expiredAt: aValidActivatePubKeyPayload.expires_at
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
      detail:
        "Internal server error: Unexpected status on pop document during activation: REVOKED"
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
