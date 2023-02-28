import { ContextMiddleware } from "@pagopa/io-functions-commons/dist/src/utils/middlewares/context_middleware";
import {
  withRequestMiddlewares,
  wrapRequestHandler
} from "@pagopa/io-functions-commons/dist/src/utils/request_middleware";
import { Context } from "@azure/functions";
import { RequiredParamMiddleware } from "@pagopa/io-functions-commons/dist/src/utils/middlewares/required_param";
import { RequiredBodyPayloadMiddleware } from "@pagopa/io-functions-commons/dist/src/utils/middlewares/required_body_payload";
import {
  IResponseErrorForbiddenNotAuthorized,
  IResponseErrorInternal,
  IResponseErrorNotFound,
  IResponseErrorValidation,
  IResponseSuccessJson,
  ResponseErrorForbiddenNotAuthorized,
  ResponseErrorInternal,
  ResponseSuccessJson
} from "@pagopa/ts-commons/lib/responses";
import * as express from "express";
import { flow, pipe } from "fp-ts/lib/function";
import * as TE from "fp-ts/lib/TaskEither";
import { readableReportSimplified } from "@pagopa/ts-commons/lib/reporters";
import { JwkPublicKeyFromToken } from "@pagopa/ts-commons/lib/jwk";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { ActivatedPubKey } from "../generated/definitions/internal/ActivatedPubKey";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import { ActivatePubKeyPayload } from "../generated/definitions/internal/ActivatePubKeyPayload";
import { PubKeyStatusEnum } from "../generated/definitions/internal/PubKeyStatus";

import {
  AssertionFileName,
  RetrievedLolliPopPubKeys
} from "../model/lollipop_keys";

import { AssertionWriter, PopDocumentWriter } from "../utils/writers";
import { PopDocumentReader } from "../utils/readers";
import {
  isPendingLollipopPubKey,
  isValidLollipopPubKey,
  MASTER_HASH_ALGO,
  retrievedLollipopKeysToApiActivatedPubKey,
  getAlgoFromAssertionRef,
  getAllAssertionsRef
} from "../utils/lollipopKeys";

export const activatePubKeyForAssertionRef = (
  popDocumentWriter: PopDocumentWriter,
  context: Context
) => (
  assertionFileName: AssertionFileName,
  assertionRef: AssertionRef,
  body: ActivatePubKeyPayload,
  pubKey: NonEmptyString
): TE.TaskEither<IResponseErrorInternal, RetrievedLolliPopPubKeys> =>
  pipe(
    popDocumentWriter({
      assertionFileName,
      assertionRef,
      assertionType: body.assertion_type,
      expiredAt: body.expired_at,
      fiscalCode: body.fiscal_code,
      pubKey,
      status: PubKeyStatusEnum.VALID
    }),
    TE.mapLeft(error => {
      const err = error.detail;
      context.log.error(err);
      return ResponseErrorInternal(err);
    })
  );

const logAndReturnAnInternalErrorResponse = (
  message: string,
  context: Context
): IResponseErrorInternal => {
  context.log.error(message);
  return ResponseErrorInternal(message);
};

// -------------------------------
// Handler
// -------------------------------

type ActivatePubKeyHandler = (
  context: Context,
  assertion_ref: AssertionRef,
  body: ActivatePubKeyPayload
) => Promise<
  | IResponseSuccessJson<ActivatedPubKey>
  | IResponseErrorNotFound
  | IResponseErrorValidation
  | IResponseErrorForbiddenNotAuthorized
  | IResponseErrorInternal
>;
export const ActivatePubKeyHandler = (
  popDocumentReader: PopDocumentReader,
  popDocumentWriter: PopDocumentWriter,
  assertionWriter: AssertionWriter
): ActivatePubKeyHandler => (
  context,
  assertion_ref,
  body
): ReturnType<ActivatePubKeyHandler> =>
  pipe(
    popDocumentReader(assertion_ref),
    TE.mapLeft(error => {
      const err = `Error while reading pop document: ${error.kind}`;
      return logAndReturnAnInternalErrorResponse(err, context);
    }),
    TE.filterOrElseW(isPendingLollipopPubKey, doc => {
      const err = `Unexpected status on pop document during activation: ${doc.status}`;
      context.log.error(err);
      return ResponseErrorForbiddenNotAuthorized;
    }),
    TE.bindTo("popDocument"),
    TE.bindW("assertionFileName", () =>
      pipe(
        `${body.fiscal_code}-${assertion_ref}`,
        AssertionFileName.decode,
        TE.fromEither,
        TE.mapLeft(errors => {
          const err = `Could not decode assertionFileName | ${readableReportSimplified(
            errors
          )}`;
          return logAndReturnAnInternalErrorResponse(err, context);
        }),
        TE.chainFirst(assertionFileName =>
          pipe(
            assertionWriter(assertionFileName, body.assertion),
            TE.mapLeft(error => {
              const err = error.detail;
              return logAndReturnAnInternalErrorResponse(err, context);
            })
          )
        )
      )
    ),
    TE.bindW("jwkPubKeyFromString", ({ popDocument }) =>
      pipe(
        popDocument.pubKey,
        JwkPublicKeyFromToken.decode,
        TE.fromEither,
        TE.mapLeft(errors => {
          const err = `Could not decode public key | ${readableReportSimplified(
            errors
          )}`;
          return logAndReturnAnInternalErrorResponse(err, context);
        })
      )
    ),
    TE.bindW("assertionRefs", ({ popDocument, jwkPubKeyFromString }) =>
      pipe(
        getAllAssertionsRef(
          MASTER_HASH_ALGO,
          getAlgoFromAssertionRef(popDocument.assertionRef),
          jwkPubKeyFromString
        ),
        TE.mapLeft((error: Error) => {
          const err = error.message;
          return logAndReturnAnInternalErrorResponse(err, context);
        })
      )
    ),
    TE.bindW(
      "retrievedPopDocument",
      ({ popDocument, assertionRefs, assertionFileName }) =>
        activatePubKeyForAssertionRef(popDocumentWriter, context)(
          assertionFileName,
          assertionRefs.master,
          body,
          popDocument.pubKey
        )
    ),
    TE.chain(
      ({
        assertionRefs,
        assertionFileName,
        popDocument,
        retrievedPopDocument
      }) =>
        assertionRefs.used
          ? activatePubKeyForAssertionRef(popDocumentWriter, context)(
              assertionFileName,
              assertionRefs.used,
              body,
              popDocument.pubKey
            )
          : TE.of(retrievedPopDocument)
    ),
    TE.chainW(
      flow(
        TE.fromPredicate(isValidLollipopPubKey, () => {
          const err = `Unexpected retrievedPopDocument with a not VALID status`;
          return logAndReturnAnInternalErrorResponse(err, context);
        }),
        TE.map(retrievedLollipopKeysToApiActivatedPubKey),
        TE.map(ResponseSuccessJson)
      )
    ),
    TE.toUnion
  )();

export const ActivatePubKey = (
  popDocumentReader: PopDocumentReader,
  popDocumentWriter: PopDocumentWriter,
  assertionWriter: AssertionWriter
): express.RequestHandler => {
  const handler = ActivatePubKeyHandler(
    popDocumentReader,
    popDocumentWriter,
    assertionWriter
  );

  const middlewaresWrap = withRequestMiddlewares(
    ContextMiddleware(),
    RequiredParamMiddleware("assertion_ref", AssertionRef),
    RequiredBodyPayloadMiddleware(ActivatePubKeyPayload)
  );

  return wrapRequestHandler(middlewaresWrap(handler));
};
