import { pipe } from "fp-ts/lib/function";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import * as TE from "fp-ts/lib/TaskEither";
import { CosmosErrors } from "@pagopa/io-functions-commons/dist/src/utils/cosmosdb_model";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";
import { ActivatedPubKey } from "../generated/definitions/internal/ActivatedPubKey";
import { LolliPOPKeysModel } from "../model/lollipop_keys";
import { BlobService } from "azure-storage";

// TODO: right: retrievedPopDocument
// left: errors
export type PopDocumentWriter = (
  assertionRef: AssertionRef
) => TE.TaskEither<CosmosErrors, ActivatedPubKey>;

// TODO:CHANGE LEFT/RIGHT
export type AssertionWriter = (
  assertionFileName: string,
  assertion: NonEmptyString
) => TE.TaskEither<unknown, unknown>;

//IMPLEMENTATION
export const getPopDocumentWriter = (
  lollipopKeysModel: LolliPOPKeysModel
): PopDocumentWriter => assertionRef => {
  return TE.of({} as ActivatedPubKey);
};

export const getAssertionWriter = (
  assertionBlobService: BlobService
): AssertionWriter => (assertionFileName, assertion) => {
  return TE.of({});
};
