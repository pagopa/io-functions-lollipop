import * as TE from "fp-ts/TaskEither";
import * as E from "fp-ts/Either";
import * as O from "fp-ts/Option";

import { LolliPOPKeysModel } from "../../model/lollipop_keys";
import { getPopDocumentReader } from "../readers";

import {
  aRetrievedPendingLollipopPubKeySha256,
  aValidSha256AssertionRef
} from "../../__mocks__/lollipopPubKey.mock";
import { ErrorResponse } from "@azure/cosmos";

// --------------------------
// Mocks
// --------------------------

const findLastVersionByModelIdMock = jest
  .fn()
  .mockImplementation(() =>
    TE.of(O.some(aRetrievedPendingLollipopPubKeySha256))
  );

const upsertMock = jest.fn().mockImplementation(() => TE.of({}));

const lollipopPubKeysModelMock = ({
  findLastVersionByModelId: findLastVersionByModelIdMock,
  upsert: upsertMock
} as unknown) as LolliPOPKeysModel;

// --------------------------
// Tests
// --------------------------

describe("PopDocumentReader", () => {
  beforeEach(() => jest.clearAllMocks());

  it("should return the existing popDocument", async () => {
    const popDocumentReader = getPopDocumentReader(lollipopPubKeysModelMock);

    const result = await popDocumentReader(aValidSha256AssertionRef)();
    expect(result).toEqual(E.right(aRetrievedPendingLollipopPubKeySha256));
  });

  it("should return NotFound if document does not exists", async () => {
    findLastVersionByModelIdMock.mockImplementationOnce(() => TE.of(O.none));
    const popDocumentReader = getPopDocumentReader(lollipopPubKeysModelMock);

    const result = await popDocumentReader(aValidSha256AssertionRef)();
    expect(result).toMatchObject(
      E.left({
        kind: "NotFound"
      })
    );
  });

  it("should return InternalError if an error occurred retrieving the document", async () => {
    findLastVersionByModelIdMock.mockImplementationOnce(() =>
      TE.left({
        kind: "COSMOS_ERROR_RESPONSE",
        error: { message: "an Error" } as ErrorResponse
      })
    );
    const popDocumentReader = getPopDocumentReader(lollipopPubKeysModelMock);

    const result = await popDocumentReader(aValidSha256AssertionRef)();
    expect(result).toEqual(
      E.left({
        kind: "Internal",
        detail: 'Generic error: {"message":"an Error"}'
      })
    );
  });
});
