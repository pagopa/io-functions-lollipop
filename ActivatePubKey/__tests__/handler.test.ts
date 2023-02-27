import * as TE from "fp-ts/lib/TaskEither";
import * as O from "fp-ts/lib/Option";
import * as E from "fp-ts/lib/Either";
import {
  AssertionFileName,
  LolliPOPKeysModel,
  RetrievedLolliPopPubKeys,
  TTL_VALUE_AFTER_UPDATE
} from "../../model/lollipop_keys";
import { FiscalCode, NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { AssertionTypeEnum } from "@pagopa/io-functions-commons/dist/generated/definitions/lollipop/AssertionType";
import { PubKeyStatusEnum } from "../../generated/definitions/internal/PubKeyStatus";
import { NonNegativeInteger } from "@pagopa/ts-commons/lib/numbers";
import { ActivatePubKeyHandler } from "../handler";
import { BlobService, createBlobService } from "azure-storage";
import { getPopDocumentReader } from "../../utils/readers";
import { getAssertionWriter, getPopDocumentWriter } from "../../utils/writers";
import { ActivatePubKeyPayload } from "../../generated/definitions/internal/ActivatePubKeyPayload";
import {
  retrievedLollipopKeysToApiActivatedPubKey,
  RetrievedValidPopDocument
} from "../../utils/lollipopKeys";
import * as fn_commons from "@pagopa/io-functions-commons/dist/src/utils/azure_storage";
import { getAllAssertionsRef } from "../../utils/lollipopKeys";
import { JwkPubKeyHashAlgorithmEnum } from "../../generated/definitions/internal/JwkPubKeyHashAlgorithm";
import {
  aValidJwk,
  aValidSha256AssertionRef,
  aValidSha512AssertionRef,
  toEncodedJwk
} from "../../__mocks__/lollipopPubKey.mock";
import { blobServiceMock } from "../../__mocks__/blobService.mock";

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

const contextMock = {} as any;

const LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME = "assertions" as NonEmptyString;

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
