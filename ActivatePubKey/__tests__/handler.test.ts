import * as TE from "fp-ts/lib/TaskEither";
import * as O from "fp-ts/lib/Option";
import * as E from "fp-ts/lib/Either";
import {
  AssertionFileName,
  LolliPOPKeysModel,
  RetrievedLolliPopPubKeys,
  TTL_VALUE_AFTER_UPDATE
} from "../../model/lollipop_keys";
import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";
import { FiscalCode, NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { AssertionTypeEnum } from "@pagopa/io-functions-commons/dist/generated/definitions/lollipop/AssertionType";
import { AssertionRef } from "../../generated/definitions/internal/AssertionRef";
import { PubKeyStatusEnum } from "../../generated/definitions/internal/PubKeyStatus";
import { NonNegativeInteger } from "@pagopa/ts-commons/lib/numbers";
import { ActivatePubKeyHandler } from "../handler";
import { BlobService } from "azure-storage";
import { getPopDocumentReader } from "../../utils/readers";
import { getAssertionWriter, getPopDocumentWriter } from "../../utils/writers";
import { ActivatePubKeyPayload } from "../../generated/definitions/internal/ActivatePubKeyPayload";
import {
  retrievedLollipopKeysToApiActivatedPubKey,
  RetrievedValidPopDocument
} from "../../utils/lollipop_keys_utils";
import * as fn_commons from "@pagopa/io-functions-commons/dist/src/utils/azure_storage";
import * as jose from "jose";
import { getAllAssertionsRef } from "../../utils/lollipopKeys";
import { JwkPubKeyHashAlgorithmEnum } from "../../generated/definitions/internal/JwkPubKeyHashAlgorithm";

const aFiscalCode = "SPNDNL80A13Y555X" as FiscalCode;

const aSha256AssertionRef = "sha256-jRW8AFXvVzqDCmH64b64dWogeGAS9ZMIaI2--1-oaBo" as AssertionRef;
const aSha384AssertionRef = "sha384-zCwmHNNQ-I79Ulo7N2YqVmwCRhOjCHLX6Wh7ex-GPua_wJyeIUlo74RwpeyctSIQ" as AssertionRef;
const aSha512AssertionRef = "sha512-GWle_6LVmGOw2ViVkYxacREmniT7mVHRbvLsX6OqqhDU9TBuej3Qxgbmcnh9cr2K_INXIVtoVBGG-6amMneQfg" as AssertionRef;

const anInvalidJwk: JwkPublicKey = {
  alg: "",
  e: "e",
  kty: "RSA",
  n: "n"
};
const aValidJwk: JwkPublicKey = {
  kty: "EC",
  crv: "P-256",
  x: "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
  y: "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
};

const toEncodedJwk = (jwk: JwkPublicKey) =>
  jose.base64url.encode(JSON.stringify(jwk)) as NonEmptyString;

const aValidRetrievedPopDocument: RetrievedLolliPopPubKeys = {
  pubKey: toEncodedJwk(aValidJwk),
  ttl: TTL_VALUE_AFTER_UPDATE,
  assertionType: AssertionTypeEnum.SAML,
  assertionRef: aSha256AssertionRef,
  assertionFileName: `${aFiscalCode}-${aSha256AssertionRef}` as AssertionFileName,
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
  assertionRef: aSha512AssertionRef,
  assertionFileName: `${aFiscalCode}-${aSha512AssertionRef}`
} as RetrievedValidPopDocument;

const aPendingRetrievedPopDocumentWithMasterAlgo = {
  ...aPendingRetrievedPopDocument,
  // to let this document match the master we must change the assertionRef
  // to a sha512 one
  assertionRef: aSha512AssertionRef,
  assertionFileName: `${aFiscalCode}-${aSha512AssertionRef}`
};

const upsertBlobFromObjectMock = jest.spyOn(fn_commons, "upsertBlobFromObject");

const findLastVersionByModelIdMock = jest
  .fn()
  .mockImplementation(() => TE.of(O.some({})));

const upsertMock = jest.fn().mockImplementation(() => TE.of({}));

const lollipopPubKeysModelMock = ({
  findLastVersionByModelId: findLastVersionByModelIdMock,
  upsert: upsertMock
} as unknown) as LolliPOPKeysModel;

const blobServiceMock = {} as BlobService;

const contextMock = {} as any;

const LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME = "assertions" as NonEmptyString;

describe("activatePubKey handler", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should success given valid informations when used algo != master algo", async () => {
    upsertBlobFromObjectMock.mockImplementationOnce(() =>
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
      aSha256AssertionRef,
      aPendingRetrievedPopDocument.pubKey
    )();

    if (assertionRefsResult._tag === "Left") fail();

    const res = await activatePubKeyHandler(
      contextMock,
      aSha256AssertionRef,
      aValidActivatePubKeyPayload
    );

    expect(findLastVersionByModelIdMock).toHaveBeenCalledTimes(1);
    expect(findLastVersionByModelIdMock).toHaveBeenCalledWith([
      aSha256AssertionRef
    ]);
    expect(upsertBlobFromObjectMock).toHaveBeenCalledTimes(1);
    expect(upsertBlobFromObjectMock).toHaveBeenCalledWith(
      blobServiceMock,
      LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME,
      `${aValidActivatePubKeyPayload.fiscal_code}-${aSha256AssertionRef}`,
      ""
    );
    expect(upsertMock).toHaveBeenCalledTimes(2);
    expect(upsertMock).toHaveBeenNthCalledWith(1, {
      pubKey: aPendingRetrievedPopDocument.pubKey,
      ttl: TTL_VALUE_AFTER_UPDATE,
      // the assertion Ref for masterKey is created by the getAllAssertionRefs method
      assertionRef: assertionRefsResult.right.master,
      assertionFileName: `${aFiscalCode}-${aSha256AssertionRef}`,
      status: PubKeyStatusEnum.VALID,
      assertionType: aValidActivatePubKeyPayload.assertion_type,
      fiscalCode: aValidActivatePubKeyPayload.fiscal_code,
      expiredAt: aValidActivatePubKeyPayload.expires_at
    });
    expect(upsertMock).toHaveBeenNthCalledWith(2, {
      pubKey: aPendingRetrievedPopDocument.pubKey,
      ttl: TTL_VALUE_AFTER_UPDATE,
      assertionRef: aSha256AssertionRef,
      assertionFileName: `${aFiscalCode}-${aSha256AssertionRef}`,
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
    upsertBlobFromObjectMock.mockImplementationOnce(() =>
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
      aSha512AssertionRef,
      aPendingRetrievedPopDocument.pubKey
    )();

    if (assertionRefsResult._tag === "Left") fail();

    const res = await activatePubKeyHandler(
      contextMock,
      aSha512AssertionRef,
      aValidActivatePubKeyPayload
    );

    expect(findLastVersionByModelIdMock).toHaveBeenCalledTimes(1);
    expect(findLastVersionByModelIdMock).toHaveBeenCalledWith([
      aSha512AssertionRef
    ]);
    expect(upsertBlobFromObjectMock).toHaveBeenCalledTimes(1);
    expect(upsertBlobFromObjectMock).toHaveBeenCalledWith(
      blobServiceMock,
      LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME,
      `${aValidActivatePubKeyPayload.fiscal_code}-${aSha512AssertionRef}`,
      ""
    );
    expect(upsertMock).toHaveBeenCalledTimes(1);
    expect(upsertMock).toHaveBeenCalledWith({
      pubKey: aPendingRetrievedPopDocument.pubKey,
      ttl: TTL_VALUE_AFTER_UPDATE,
      // the assertion Ref for masterKey is created by the getAllAssertionRefs method
      assertionRef: assertionRefsResult.right.master,
      assertionFileName: `${aFiscalCode}-${aSha512AssertionRef}`,
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
