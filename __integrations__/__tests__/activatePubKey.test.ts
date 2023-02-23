/* eslint-disable @typescript-eslint/no-use-before-define */
/* eslint-disable sort-keys */
import { exit } from "process";

import { CosmosClient, Database } from "@azure/cosmos";
import { createBlobService } from "azure-storage";

import * as TE from "fp-ts/TaskEither";
import * as E from "fp-ts/Either";
import * as O from "fp-ts/Option";
import { pipe } from "fp-ts/lib/function";
import { getBlobAsTextWithError } from "@pagopa/io-functions-commons/dist/src/utils/azure_storage";
import {
  createCosmosDbAndCollections,
  LOLLIPOP_COSMOSDB_COLLECTION_NAME
} from "../__mocks__/fixtures";

import { getNodeFetch } from "../utils/fetch";
import { log } from "../utils/logger";
import {
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
  toEncodedJwk
} from "../../__mocks__/lollipopPubKey.mock";
import { ActivatePubKeyPayload } from "../../generated/definitions/internal/ActivatePubKeyPayload";
import { AssertionTypeEnum } from "../../generated/definitions/internal/AssertionType";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { fetchActivatePubKey } from "../utils/client";

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

// -------------------------
// Tests
// -------------------------

describe("activatePubKey |> Success Results", () => {
  it("should succeed when valid payload is passed to the endpoint AND when algo != master", async () => {
    // TODO: replace with insert call (POST /api/v1/pubKeys)
    const retrieved = await lolliPOPKeysModel.create(aNewPopDocument)();
    const expires = new Date();

    const validActivatePubKeyPayload: ActivatePubKeyPayload = {
      assertion_type: AssertionTypeEnum.SAML,
      assertion: "aValidAssertion" as NonEmptyString,
      expires_at: expires,
      fiscal_code: aFiscalCode
    };

    const anAssertionFileNameForSha256 = `${aFiscalCode}-${aValidSha256AssertionRef}`;

    expect(retrieved._tag).toEqual("Right");

    const response = await fetchActivatePubKey(
      aValidSha256AssertionRef,
      validActivatePubKeyPayload,
      baseUrl,
      (myFetch as unknown) as typeof fetch
    );

    const assertionBlobbb = await pipe(
      getBlobAsTextWithError(
        blobService,
        LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME
      )(anAssertionFileNameForSha256),
      TE.map(O.map(JSON.parse))
    )();

    expect(assertionBlobbb).toEqual(
      E.right(O.some(validActivatePubKeyPayload.assertion))
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
