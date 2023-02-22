import { pipe } from "fp-ts/lib/function";
import * as TE from "fp-ts/lib/TaskEither";
import * as E from "fp-ts/lib/Either";
import { upsertBlobFromObject } from "@pagopa/io-functions-commons/dist/src/utils/azure_storage";
import { BlobService } from "azure-storage";
import {
  AssertionFileName,
  LolliPOPKeysModel,
  NewLolliPopPubKeys,
  RetrievedLolliPopPubKeys
} from "../model/lollipop_keys";
import {
  cosmosErrorsToString,
  ErrorKind,
  InternalError
} from "./domain_errors";
import { getConfigOrThrow } from "./config";

const config = getConfigOrThrow();

export type PopDocumentWriter = (
  item: NewLolliPopPubKeys
) => TE.TaskEither<InternalError, RetrievedLolliPopPubKeys>;

export type AssertionWriter = (
  assertionFileName: AssertionFileName,
  assertion: string
) => TE.TaskEither<InternalError, true>;

// IMPLEMENTATION
export const getPopDocumentWriter = (
  lollipopKeysModel: LolliPOPKeysModel
): PopDocumentWriter => item =>
  pipe(
    lollipopKeysModel.upsert(item),
    TE.mapLeft(error => ({
      kind: ErrorKind.Internal as const,
      detail: cosmosErrorsToString(error)
    }))
  );

export const getAssertionWriter = (
  assertionBlobService: BlobService
): AssertionWriter => (assertionFileName, assertion) =>
  pipe(
    TE.tryCatch(
      () =>
        upsertBlobFromObject(
          assertionBlobService,
          config.LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME,
          assertionFileName,
          assertion
        ),
      E.toError
    ),
    TE.chainW(TE.fromEither),
    TE.mapLeft((error: Error) => ({
      kind: ErrorKind.Internal as const,
      detail: `${error.message}`
    })),
    TE.chainW(
      TE.fromOption(() => ({
        kind: ErrorKind.Internal as const,
        detail: "Can not upload blob to storage"
      }))
    ),
    TE.map(_ => true)
  );
