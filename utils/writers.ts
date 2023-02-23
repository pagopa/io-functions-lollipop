import { pipe } from "fp-ts/lib/function";
import * as TE from "fp-ts/lib/TaskEither";
import * as E from "fp-ts/lib/Either";
import { upsertBlobFromObject } from "@pagopa/io-functions-commons/dist/src/utils/azure_storage";
import { BlobService } from "azure-storage";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
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
): PopDocumentWriter => (item): ReturnType<PopDocumentWriter> =>
  pipe(
    lollipopKeysModel.upsert(item),
    TE.mapLeft(error => ({
      detail: cosmosErrorsToString(error),
      kind: ErrorKind.Internal as const
    }))
  );

export const getAssertionWriter = (
  assertionBlobService: BlobService,
  lollipopAssertionStorageContainerName: NonEmptyString
): AssertionWriter => (
  assertionFileName,
  assertion
): ReturnType<AssertionWriter> =>
  pipe(
    TE.tryCatch(
      () =>
        upsertBlobFromObject(
          assertionBlobService,
          lollipopAssertionStorageContainerName,
          assertionFileName,
          assertion
        ),
      E.toError
    ),
    TE.chainW(TE.fromEither),
    TE.mapLeft((error: Error) => ({
      detail: `${error.message}`,
      kind: ErrorKind.Internal as const
    })),
    TE.chainW(
      TE.fromOption(() => ({
        detail: "Can not upload blob to storage",
        kind: ErrorKind.Internal as const
      }))
    ),
    TE.map(_ => true)
  );
