import * as RTE from "fp-ts/ReaderTaskEither";
import * as TE from "fp-ts/lib/TaskEither";
import { pipe } from "fp-ts/lib/function";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import {
  LolliPOPKeysModel,
  RetrievedLolliPopPubKeys
} from "../model/lollipop_keys";
import { cosmosErrorsToString, DomainError, ErrorKind } from "./errors";

export type PopDocumentReader = RTE.ReaderTaskEither<
  AssertionRef,
  DomainError,
  RetrievedLolliPopPubKeys
>;

// IMPLEMENTATIONS
export const getPopDocumentReader = (
  lollipopKeysModel: LolliPOPKeysModel
): PopDocumentReader => (
  assertionRef: AssertionRef
): ReturnType<PopDocumentReader> =>
  pipe(
    lollipopKeysModel.findLastVersionByModelId([assertionRef]),
    TE.mapLeft(error => ({
      detail: cosmosErrorsToString(error),
      kind: ErrorKind.Internal as const
    })),
    TE.chainW(TE.fromOption(() => ({ kind: ErrorKind.NotFound as const })))
  );
