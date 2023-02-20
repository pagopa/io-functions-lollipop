import * as RTE from "fp-ts/ReaderTaskEither";
import * as TE from "fp-ts/lib/TaskEither";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import { CosmosErrors } from "@pagopa/io-functions-commons/dist/src/utils/cosmosdb_model";
import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";

export type PopDocumentReader = RTE.ReaderTaskEither<
  AssertionRef,
  CosmosErrors,
  { pubKey: JwkPublicKey }
>;

// IMPLEMENTATIONS
// MOCKED ATM
export const getPopDocumentReader = (COSMOS_MODEL: any): PopDocumentReader => (
  assertionRef: AssertionRef
) => {
  return TE.of({ pubKey: {} as JwkPublicKey });
};