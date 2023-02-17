import { pipe } from "fp-ts/lib/function";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import * as TE from "fp-ts/lib/TaskEither";
import { CosmosErrors } from "@pagopa/io-functions-commons/dist/src/utils/cosmosdb_model";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";

// TODO: right: retrievedPopDocument
// left: errors
export type PopDocumentWriter = (
  assertionRef: AssertionRef
) => TE.TaskEither<CosmosErrors, unknown>;

// TODO:CHANGE LEFT/RIGHT
export type AssertionWriter = (
  assertionFileName: string,
  assertion: NonEmptyString
) => TE.TaskEither<unknown, unknown>;

//IMPLEMENTATION
export const getPopDocumentWriter = (
  COSMOS_MODEL: any
): PopDocumentWriter => assertionRef => {
  return TE.of({ resource: [] });
};

export const getAssertionWriter = (BLOB_STORAGE: any): AssertionWriter => (
  assertionFileName,
  assertion
) => {
  return TE.of({});
};
