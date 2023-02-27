/* eslint-disable @typescript-eslint/no-use-before-define */
/* eslint-disable sort-keys */
import { exit } from "process";

import { CosmosClient, Database } from "@azure/cosmos";
import { createBlobService } from "azure-storage";

import * as TE from "fp-ts/TaskEither";
import * as E from "fp-ts/Either";
import * as O from "fp-ts/Option";
import * as jose from "jose";
import { pipe } from "fp-ts/lib/function";
import { getBlobAsTextWithError } from "@pagopa/io-functions-commons/dist/src/utils/azure_storage";
import {
  createCosmosDbAndCollections,
  LOLLIPOP_COSMOSDB_COLLECTION_NAME
} from "../__mocks__/fixtures";

import { getNodeFetch } from "../utils/fetch";
import { log } from "../utils/logger";
import {
  AssertionFileName,
  LolliPOPKeysModel,
  NewLolliPopPubKeys,
  TTL_VALUE_AFTER_UPDATE,
  TTL_VALUE_FOR_RESERVATION
} from "../../model/lollipop_keys";

import {
  WAIT_MS,
  SHOW_LOGS,
  COSMOSDB_URI,
  COSMOSDB_KEY,
  COSMOSDB_NAME,
  QueueStorageConnection
} from "../env";
import { createBlobs } from "../__mocks__/utils/azure_storage";
import { PubKeyStatusEnum } from "../../generated/definitions/internal/PubKeyStatus";
import {
  aFiscalCode,
  aValidJwk,
  aValidSha256AssertionRef,
  aValidSha512AssertionRef,
  toEncodedJwk
} from "../../__mocks__/lollipopPubKey.mock";
import { ActivatePubKeyPayload } from "../../generated/definitions/internal/ActivatePubKeyPayload";
import { AssertionTypeEnum } from "../../generated/definitions/internal/AssertionType";
import { FiscalCode, NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { fetchActivatePubKey } from "../utils/client";
import { AssertionRef } from "../../generated/definitions/internal/AssertionRef";
import { calculateJwkThumbprint } from "jose";
import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";
import { JwkPubKeyHashAlgorithmEnum } from "../../generated/definitions/internal/JwkPubKeyHashAlgorithm";

const MAX_ATTEMPT = 50;

jest.setTimeout(WAIT_MS * MAX_ATTEMPT);

const baseUrl = "http://function:7071";
const myFetch = getNodeFetch();

const LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME = "assertions";

// ----------------
// Setup dbs
// ----------------

const blobService = createBlobService(QueueStorageConnection);

// @ts-ignore
const cosmosClient = new CosmosClient({
  endpoint: COSMOSDB_URI,
  key: COSMOSDB_KEY
});

// eslint-disable-next-line functional/no-let
let database: Database;

// Wait some time
beforeAll(async () => {
  database = await pipe(
    createCosmosDbAndCollections(cosmosClient, COSMOSDB_NAME),
    TE.getOrElse(e => {
      throw Error("Cannot create infra resources");
    })
  )();
  await pipe(
    createBlobs(blobService, [LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME]),
    TE.getOrElse(() => {
      throw Error("Cannot create azure storage");
    })
  )();

  await waitFunctionToSetup();
});

beforeEach(() => {
  jest.clearAllMocks();
});

const cosmosInstance = cosmosClient.database(COSMOSDB_NAME);
const container = cosmosInstance.container(LOLLIPOP_COSMOSDB_COLLECTION_NAME);
const lolliPOPKeysModel = new LolliPOPKeysModel(container);

const aNewPopDocument: NewLolliPopPubKeys = {
  pubKey: toEncodedJwk(aValidJwk),
  ttl: TTL_VALUE_FOR_RESERVATION,
  assertionRef: aValidSha256AssertionRef,
  status: PubKeyStatusEnum.PENDING
};

const expires = new Date();

const validActivatePubKeyPayload: ActivatePubKeyPayload = {
  assertion_type: AssertionTypeEnum.SAML,
  assertion: "aValidAssertion" as NonEmptyString,
  expires_at: expires,
  fiscal_code: aFiscalCode
};

// this method generates new JWK for use in the describe below
const generateJwkForTest = async (): Promise<JwkPublicKey> => {
  const keyPair = await jose.generateKeyPair("ES256");
  return (await jose.exportJWK(keyPair.publicKey)) as JwkPublicKey;
};

const generateAssertionRefForTest = async (
  jwk: JwkPublicKey,
  algo: JwkPubKeyHashAlgorithmEnum = JwkPubKeyHashAlgorithmEnum.sha256
): Promise<AssertionRef> => {
  const thumbprint = await jose.calculateJwkThumbprint(jwk, algo);
  return `${algo}-${thumbprint}` as AssertionRef;
};

// -------------------------
// Tests
// -------------------------

describe("activatePubKey |> Validation Failures", () => {
  it("should fail when an invalid assertionRef is passed to the endpoint", async () => {
    const anInvalidAssertionRef = `anInvalidAssertionRef`;

    const response = await fetchActivatePubKey(
      anInvalidAssertionRef,
      validActivatePubKeyPayload,
      baseUrl,
      (myFetch as unknown) as typeof fetch
    );

    expect(response.status).toEqual(400);
    const body = await response.json();
    expect(body).toMatchObject({
      status: 400,
      title: "Invalid AssertionRef"
    });
  });

  it("should fail when an invalid payload is passed to the endpoint", async () => {
    const response = await fetchActivatePubKey(
      aValidSha256AssertionRef,
      { ...validActivatePubKeyPayload, fiscal_code: "anInvalidFiscalCode" },
      baseUrl,
      (myFetch as unknown) as typeof fetch
    );

    expect(response.status).toEqual(400);
    const body = await response.json();
    expect(body).toMatchObject({
      status: 400,
      title: "Invalid ActivatePubKeyPayload"
    });
  });
});

describe("activatePubKey |> Failures", () => {
  it("should return 404 when document cannot be found in cosmos", async () => {
    const response = await fetchActivatePubKey(
      aValidSha256AssertionRef,
      validActivatePubKeyPayload,
      baseUrl,
      (myFetch as unknown) as typeof fetch
    );

    expect(response.status).toEqual(404);
    const body = await response.json();
    expect(body).toMatchObject({
      status: 404,
      title: "NotFound"
    });
  });

  it("should return 500 when the retrieved pop document has status != PENDING", async () => {
    const randomJwk = await generateJwkForTest();
    const randomAssertionRef = await generateAssertionRefForTest(randomJwk);
    const randomAssertionFileName = `${aFiscalCode}-${randomAssertionRef}` as AssertionFileName;

    const randomNewPopDocument: NewLolliPopPubKeys = {
      pubKey: toEncodedJwk(randomJwk),
      ttl: TTL_VALUE_FOR_RESERVATION,
      assertionRef: randomAssertionRef,
      status: PubKeyStatusEnum.REVOKED,
      assertionFileName: randomAssertionFileName,
      assertionType: AssertionTypeEnum.SAML,
      fiscalCode: aFiscalCode,
      expiredAt: expires
    };
    const randomActivatePubKeyPayload: ActivatePubKeyPayload = {
      fiscal_code: aFiscalCode,
      assertion: "aValidAssertion" as NonEmptyString,
      assertion_type: AssertionTypeEnum.SAML,
      expires_at: expires
    };

    const res = await lolliPOPKeysModel.create(randomNewPopDocument)();

    expect(res._tag).toEqual("Right");

    const response = await fetchActivatePubKey(
      randomAssertionRef,
      randomActivatePubKeyPayload,
      baseUrl,
      (myFetch as unknown) as typeof fetch
    );

    expect(response.status).toEqual(500);
    const body = await response.json();
    expect(body).toMatchObject({
      status: 500,
      title: "Internal server error",
      detail: "Unexpected status on pop document during activation: REVOKED"
    });
  });
});

describe("activatePubKey |> Success Results", () => {
  it("should succeed when valid payload is passed to the endpoint AND when algo != master", async () => {
    // TODO: replace with insert call (POST /api/v1/pubKeys)
    const retrieved = await lolliPOPKeysModel.create(aNewPopDocument)();

    const anAssertionFileNameForSha256 = `${aFiscalCode}-${aValidSha256AssertionRef}`;

    expect(retrieved._tag).toEqual("Right");

    const response = await fetchActivatePubKey(
      aValidSha256AssertionRef,
      validActivatePubKeyPayload,
      baseUrl,
      (myFetch as unknown) as typeof fetch
    );

    expect(response.status).toEqual(200);
    const body = await response.json();
    expect(body).toMatchObject({
      fiscal_code: validActivatePubKeyPayload.fiscal_code,
      expires_at: validActivatePubKeyPayload.expires_at.toISOString(),
      assertion_type: validActivatePubKeyPayload.assertion_type,
      assertion_ref: aValidSha256AssertionRef,
      assertion_file_name: anAssertionFileNameForSha256,
      pub_key: toEncodedJwk(aValidJwk),
      status: PubKeyStatusEnum.VALID,
      ttl: TTL_VALUE_AFTER_UPDATE,
      version: 1
    });

    // Check values on storages

    const assertionBlob = await pipe(
      getBlobAsTextWithError(
        blobService,
        LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME
      )(anAssertionFileNameForSha256),
      TE.map(O.map(JSON.parse))
    )();

    expect(assertionBlob).toEqual(
      E.right(O.some(validActivatePubKeyPayload.assertion))
    );

    // Check used key
    const sha256Document = await lolliPOPKeysModel.findLastVersionByModelId([
      aValidSha256AssertionRef
    ])();

    expect(sha256Document).toEqual(
      E.right(
        O.some(
          expect.objectContaining({
            assertionRef: aValidSha256AssertionRef,
            assertionFileName: anAssertionFileNameForSha256,
            status: PubKeyStatusEnum.VALID
          })
        )
      )
    );

    // Check master document
    const masterDocument = await lolliPOPKeysModel.findLastVersionByModelId([
      aValidSha512AssertionRef
    ])();

    expect(masterDocument).toEqual(
      E.right(
        O.some(
          expect.objectContaining({
            assertionRef: aValidSha512AssertionRef,
            assertionFileName: anAssertionFileNameForSha256,
            status: PubKeyStatusEnum.VALID,
            version: 0
          })
        )
      )
    );
  });

  it("should succeed when valid payload is passed to the endpoint AND when algo == master", async () => {
    const randomJwk = await generateJwkForTest();
    const randomAssertionRef = await generateAssertionRefForTest(
      randomJwk,
      JwkPubKeyHashAlgorithmEnum.sha512
    );
    const aNewPopDocumentWithMasterAlgo: NewLolliPopPubKeys = {
      ...aNewPopDocument,
      assertionRef: randomAssertionRef,
      pubKey: toEncodedJwk(randomJwk)
    };

    const randomAssertionFileName = `${validActivatePubKeyPayload.fiscal_code}-${randomAssertionRef}`;

    // TODO: replace with insert call (POST /api/v1/pubKeys)
    const retrieved = await lolliPOPKeysModel.create(
      aNewPopDocumentWithMasterAlgo
    )();

    expect(retrieved._tag).toEqual("Right");

    const response = await fetchActivatePubKey(
      randomAssertionRef,
      validActivatePubKeyPayload,
      baseUrl,
      (myFetch as unknown) as typeof fetch
    );

    expect(response.status).toEqual(200);
    const body = await response.json();
    expect(body).toMatchObject({
      fiscal_code: validActivatePubKeyPayload.fiscal_code,
      expires_at: validActivatePubKeyPayload.expires_at.toISOString(),
      assertion_type: validActivatePubKeyPayload.assertion_type,
      assertion_ref: randomAssertionRef,
      assertion_file_name: randomAssertionFileName,
      pub_key: toEncodedJwk(randomJwk),
      status: PubKeyStatusEnum.VALID,
      ttl: TTL_VALUE_AFTER_UPDATE,
      version: 1
    });

    // Check values on storages

    const assertionBlob = await pipe(
      getBlobAsTextWithError(
        blobService,
        LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME
      )(randomAssertionFileName),
      TE.map(O.map(JSON.parse))
    )();

    expect(assertionBlob).toEqual(
      E.right(O.some(validActivatePubKeyPayload.assertion))
    );

    // Check master document(the only one present)
    const masterDocument = await lolliPOPKeysModel.findLastVersionByModelId([
      randomAssertionRef
    ])();

    expect(masterDocument).toEqual(
      E.right(
        O.some(
          expect.objectContaining({
            assertionRef: randomAssertionRef,
            assertionFileName: randomAssertionFileName,
            status: PubKeyStatusEnum.VALID,
            version: 1
          })
        )
      )
    );
  });
});

// -----------------------
// utils
// -----------------------

const delay = (ms: number): Promise<void> =>
  new Promise(resolve => setTimeout(resolve, ms));

const waitFunctionToSetup = async (): Promise<void> => {
  log("ENV: ", COSMOSDB_URI, WAIT_MS, SHOW_LOGS);
  // eslint-disable-next-line functional/no-let
  let i = 0;
  while (i < MAX_ATTEMPT) {
    log("Waiting the function to setup..");
    try {
      await myFetch(baseUrl + "/info");
      break;
    } catch (e) {
      log("Waiting the function to setup..");
      await delay(WAIT_MS);
      i++;
    }
  }
  if (i >= MAX_ATTEMPT) {
    log("Function unable to setup in time");
    exit(1);
  }
};
