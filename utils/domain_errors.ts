import { CosmosErrors } from "@pagopa/io-functions-commons/dist/src/utils/cosmosdb_model";
import { errorsToReadableMessages } from "@pagopa/ts-commons/lib/reporters";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { pipe } from "fp-ts/function";

export enum ErrorKind {
  NotFound = "NotFound",
  Internal = "Internal"
}

export type InternalError = {
  kind: ErrorKind.Internal;
  detail: string;
};

export type NotFoundError = {
  kind: ErrorKind.NotFound;
};

export type DomainError = InternalError | NotFoundError;

export const cosmosErrorsToString = (errs: CosmosErrors): NonEmptyString =>
  pipe(
    errs.kind === "COSMOS_EMPTY_RESPONSE"
      ? "Empty response"
      : errs.kind === "COSMOS_DECODING_ERROR"
      ? "Decoding error: " + errorsToReadableMessages(errs.error).join("/")
      : errs.kind === "COSMOS_CONFLICT_RESPONSE"
      ? "Conflict error"
      : "Generic error: " + JSON.stringify(errs.error),

    errorString => errorString as NonEmptyString
  );
