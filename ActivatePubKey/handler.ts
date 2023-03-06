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
import { AssertionFileName } from "../generated/definitions/internal/AssertionFileName";

import { RetrievedLolliPopPubKeys } from "../model/lollipop_keys";

import { AssertionWriter, PopDocumentWriter } from "../utils/writers";
import { PublicKeyDocumentReader } from "../utils/readers";
import {
  isPendingLollipopPubKey,
  isValidLollipopPubKey,
  MASTER_HASH_ALGO,
  retrievedLollipopKeysToApiActivatedPubKey,
  getAlgoFromAssertionRef,
  getAllAssertionsRef
} from "../utils/lollipopKeys";
import { logAndReturnResponse } from "../utils/errors";

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

// -------------------------------
// Handler
// -------------------------------

type ActivatePubKeyHandler = (
  context: Context,
  assertion_ref: AssertionRef,
  body: ActivatePubKeyPayload
) => Promise<
  | IResponseSuccessJson<ActivatedPubKey>
  | IResponseErrorValidation
  | IResponseErrorForbiddenNotAuthorized
  | IResponseErrorInternal
>;
export const ActivatePubKeyHandler = (
  publicKeyDocumentReader: PublicKeyDocumentReader,
  popDocumentWriter: PopDocumentWriter,
  assertionWriter: AssertionWriter
): ActivatePubKeyHandler => (
  context,
  assertion_ref,
  body
): ReturnType<ActivatePubKeyHandler> =>
  pipe(
    publicKeyDocumentReader(assertion_ref),
    TE.mapLeft(error =>
      logAndReturnResponse(
        context,
        ResponseErrorInternal(`Error while reading pop document: ${error.kind}`)
      )
    ),
    TE.filterOrElseW(isPendingLollipopPubKey, doc =>
      logAndReturnResponse(
        context,
        ResponseErrorForbiddenNotAuthorized,
        `Unexpected status on pop document during activation: ${doc.status}`
      )
    ),
    TE.bindTo("popDocument"),
    TE.bindW("assertionFileName", () =>
      pipe(
        `${body.fiscal_code}-${assertion_ref}`,
        AssertionFileName.decode,
        TE.fromEither,
        TE.mapLeft(errors =>
          logAndReturnResponse(
            context,
            ResponseErrorInternal(
              `Could not decode assertionFileName | ${readableReportSimplified(
                errors
              )}`
            )
          )
        ),
        TE.chainFirst(assertionFileName =>
          pipe(
            assertionWriter(assertionFileName, body.assertion),
            TE.mapLeft(error =>
              logAndReturnResponse(context, ResponseErrorInternal(error.detail))
            )
          )
        )
      )
    ),
    TE.bindW("jwkPubKeyFromString", ({ popDocument }) =>
      pipe(
        popDocument.pubKey,
        JwkPublicKeyFromToken.decode,
        TE.fromEither,
        TE.mapLeft(errors =>
          logAndReturnResponse(
            context,
            ResponseErrorInternal(
              `Could not decode public key | ${readableReportSimplified(
                errors
              )}`
            )
          )
        )
      )
    ),
    TE.bindW("assertionRefs", ({ popDocument, jwkPubKeyFromString }) =>
      pipe(
        getAllAssertionsRef(
          MASTER_HASH_ALGO,
          getAlgoFromAssertionRef(popDocument.assertionRef),
          jwkPubKeyFromString
        ),
        TE.mapLeft((error: Error) =>
          logAndReturnResponse(context, ResponseErrorInternal(error.message))
        )
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
        TE.fromPredicate(isValidLollipopPubKey, () =>
          logAndReturnResponse(
            context,
            ResponseErrorInternal(
              `Unexpected retrievedPopDocument with a not VALID status`
            )
          )
        ),
        TE.map(retrievedLollipopKeysToApiActivatedPubKey),
        TE.map(ResponseSuccessJson)
      )
    ),
    TE.toUnion
  )();

export const ActivatePubKey = (
  publicKeyDocumentReader: PublicKeyDocumentReader,
  popDocumentWriter: PopDocumentWriter,
  assertionWriter: AssertionWriter
): express.RequestHandler => {
  const handler = ActivatePubKeyHandler(
    publicKeyDocumentReader,
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
