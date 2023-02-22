import * as RTE from "fp-ts/ReaderTaskEither";
import * as TE from "fp-ts/lib/TaskEither";
import { flow, pipe } from "fp-ts/lib/function";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import {
  LolliPOPKeysModel,
  RetrievedLolliPopPubKeys
} from "../model/lollipop_keys";
import { cosmosErrorsToString, DomainError, ErrorKind } from "./domain_errors";

export type PopDocumentReader = RTE.ReaderTaskEither<
  AssertionRef,
  DomainError,
  RetrievedLolliPopPubKeys
>;

// IMPLEMENTATIONS
export const getPopDocumentReader = (
  lollipopKeysModel: LolliPOPKeysModel
): PopDocumentReader => (assertionRef: AssertionRef) =>
  pipe(
    lollipopKeysModel.findLastVersionByModelId([assertionRef]),
    TE.mapLeft(error => ({
      kind: ErrorKind.Internal as const,
      detail: cosmosErrorsToString(error)
    })),
    TE.chainW(
      flow(TE.fromOption(() => ({ kind: ErrorKind.NotFound as const })))
    )
  );
