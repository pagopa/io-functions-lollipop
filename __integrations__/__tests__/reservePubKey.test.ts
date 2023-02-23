/* eslint-disable @typescript-eslint/no-use-before-define */
/* eslint-disable sort-keys */
import { exit } from "process";

import { CosmosClient, Database } from "@azure/cosmos";
import { createBlobService } from "azure-storage";

import * as TE from "fp-ts/TaskEither";
import { pipe } from "fp-ts/lib/function";

import { createCosmosDbAndCollections } from "../__mocks__/fixtures";

import { getNodeFetch } from "../utils/fetch";
import { log } from "../utils/logger";

import {
  WAIT_MS,
  SHOW_LOGS,
  COSMOSDB_URI,
  COSMOSDB_KEY,
  COSMOSDB_NAME
} from "../env";

const MAX_ATTEMPT = 50;

jest.setTimeout(WAIT_MS * MAX_ATTEMPT);

const baseUrl = "http://function:7071";
const fetch = getNodeFetch();

// ----------------
// Setup dbs
// ----------------

console.log("COSMOSURI " + COSMOSDB_URI);
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
      throw Error("Cannot create db");
    })
  )();

  await waitFunctionToSetup();
});

beforeEach(() => {
  jest.clearAllMocks();
});

// -------------------------
// Tests
// -------------------------

const aPubKey = {
  algo: "sha256",
  pub_key: {
    kty: "EC",
    crv: "secp256k1",
    x: "Q8K81dZcC4DdKl52iW7bT0ubXXm2amN835M_v5AgpSE",
    y: "lLsw82Q414zPWPluI5BmdKHK6XbFfinc8aRqbZCEv0A"
  }
};
const aPubKeyAssertionRef =
  "sha256-LWmgzxnrIhywpNW0mctCFWfh2CptjGJJN_H2_FLN2fg";

const anotherPubKey = {
  algo: "sha256",
  pub_key: {
    kty: "EC",
    crv: "secp256k1",
    x: "Q8K81dZcC4DdKl52iW7bT0ubXXm2amN835M_v5AgpSF",
    y: "lLsw82Q414zPWPluI5BmdKHK6XbFfinc8aRqbZCEv0A"
  }
};

const RESERVE_PUB_KEY_PATH = "api/v1/pubkeys";
const fetchReservePubKey = (body: unknown) =>
  fetch(`${baseUrl}/${RESERVE_PUB_KEY_PATH}`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

describe("ReservePubKey", () => {

  test("GIVEN a new public key WHEN reserve the key THEN return a success contianing the assertion ref", async () => {
    const result = await fetchReservePubKey(aPubKey);
    const content = await result.json();
    expect(content).toEqual(
      expect.objectContaining({ assertion_ref: aPubKeyAssertionRef })
    );
  });

  test("GIVEN an already reserved public key WHEN reserve the key with any algo THEN return a conflict", async () => {
    const reserve = await fetchReservePubKey(anotherPubKey);
    expect(reserve.status).toEqual(201);

    const fail = await fetchReservePubKey(anotherPubKey);
    expect(fail.status).toEqual(409);

    const failWith512 = await fetchReservePubKey({
      ...anotherPubKey,
      algo: "sha512"
    });
    expect(failWith512.status).toEqual(409);

    const failWith384 = await fetchReservePubKey({
      ...anotherPubKey,
      algo: "sha384"
    });
    expect(failWith384.status).toEqual(409);
  });

  test("GIVEN an malformed public key WHEN reserve the key THEN return a bad request", async () => {
    const reserve = await fetchReservePubKey({ wrong: "wrong" });
    expect(reserve.status).toEqual(400);
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
      await fetch(baseUrl + "/info");
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
