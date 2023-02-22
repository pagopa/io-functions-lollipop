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
  ResponseErrorInternal,
  ResponseErrorNotFound,
  ResponseSuccessJson
} from "@pagopa/ts-commons/lib/responses";
import * as express from "express";
import { pipe, flow } from "fp-ts/lib/function";
import * as TE from "fp-ts/lib/TaskEither";
import * as O from "fp-ts/lib/Option";
import * as jose from "jose";
import {
  JwkPublicKey,
  JwkPublicKeyFromToken
} from "@pagopa/ts-commons/lib/jwk";
import { BlobService } from "azure-storage";
import { readableReport } from "@pagopa/ts-commons/lib/reporters";
import { ActivatedPubKey } from "../generated/definitions/internal/ActivatedPubKey";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import { ActivatePubKeyPayload } from "../generated/definitions/internal/ActivatePubKeyPayload";
import {
  AssertionWriter,
  getAssertionWriter,
  getPopDocumentWriter,
  PopDocumentWriter
} from "../utils/writers";
import { getPopDocumentReader, PopDocumentReader } from "../utils/readers";
import { AssertionRefSha256 } from "../generated/definitions/internal/AssertionRefSha256";
import { AssertionRefSha384 } from "../generated/definitions/internal/AssertionRefSha384";
import { JwkPubKeyHashAlgorithmEnum } from "../generated/definitions/internal/JwkPubKeyHashAlgorithm";
import {
  AssertionFileName,
  LolliPOPKeysModel,
  TTL_VALUE_AFTER_UPDATE,
  ValidLolliPopPubKeys
} from "../model/lollipop_keys";
import { PubKeyStatusEnum } from "../generated/definitions/internal/PubKeyStatus";
import {
  calculateThumbprint,
  retrievedLollipopKeysToApiActivatedPubKey,
  retrievedValidPopDocument
} from "../utils/lollipop_keys_utils";
import { getAllAssertionsRef } from "../utils/lollipopKeys";
import { ErrorKind } from "../utils/domain_errors";

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
  PopDocumentReader: PopDocumentReader,
  PopDocumentWriter: PopDocumentWriter,
  AssertionWriter: AssertionWriter
): ActivatePubKeyHandler => (_, assertion_ref, body) => {
  /*
   *   STEPS:
   *   1. create assertionFileName(based on CF and assertion_ref)
   *   2. write assertion to blob storage(assertionFileName)
   *   3. upsert PopDocument
   *   4. if algo != sha512 upsert PopDocument with sha512 prefix
   *   */

  const errorOrAssertionFileName = AssertionFileName.decode(
    `${body.fiscal_code}-${assertion_ref}`
  );

  return pipe(
    PopDocumentReader(assertion_ref),
    TE.mapLeft(errors =>
      errors.kind === ErrorKind.NotFound
        ? ResponseErrorNotFound(errors.kind, "Could not find popDocument")
        : ResponseErrorInternal(errors.detail)
    ),
    TE.chainW(popDocument =>
      pipe(
        errorOrAssertionFileName,
        TE.fromEither,
        TE.bindTo("assertionFileName"),
        TE.mapLeft(errors =>
          ResponseErrorInternal(
            `Could not decode assertionFileName | ${readableReport(errors)}`
          )
        ),
        TE.chainFirst(({ assertionFileName }) =>
          pipe(
            AssertionWriter(assertionFileName, body.assertion),
            TE.mapLeft(error => ResponseErrorInternal(error.detail))
          )
        ),
        TE.bindW("assertionRefs", () =>
          pipe(
            getAllAssertionsRef(JwkPubKeyHashAlgorithmEnum.sha512, popDocument),
            TE.mapLeft((error: Error) => ResponseErrorInternal(error.message))
          )
        ),
        TE.bind("retrievedPopDocument", ({ assertionRefs }) =>
          pipe(
            PopDocumentWriter({
              pubKey: popDocument.pubKey,
              ttl: TTL_VALUE_AFTER_UPDATE,
              assertionRef: assertionRefs.master,
              assertionFileName: `${body.fiscal_code}-${assertionRefs.master}` as AssertionFileName,
              status: PubKeyStatusEnum.VALID,
              assertionType: body.assertion_type,
              fiscalCode: body.fiscal_code,
              expiredAt: body.expires_at
            }),
            TE.mapLeft(error => ResponseErrorInternal(error.detail))
          )
        ),
        TE.bind(
          "retrievedUsedPopDocument",
          ({ assertionRefs, assertionFileName }) =>
            pipe(
              assertionRefs.used,
              TE.fromNullable(() => null),
              TE.foldW(
                () => TE.right(null),
                u =>
                  pipe(
                    PopDocumentWriter({
                      pubKey: popDocument.pubKey,
                      ttl: TTL_VALUE_AFTER_UPDATE,
                      assertionRef: u,
                      assertionFileName,
                      status: PubKeyStatusEnum.VALID,
                      assertionType: body.assertion_type,
                      fiscalCode: body.fiscal_code,
                      expiredAt: body.expires_at
                    }),
                    TE.mapLeft(error => ResponseErrorInternal(error.detail))
                  )
              )
            )
        ),
        TE.map(({ retrievedPopDocument, retrievedUsedPopDocument }) =>
          pipe(
            retrievedUsedPopDocument,
            O.fromNullable,
            O.getOrElse(() => retrievedPopDocument)
          )
        ),
        TE.chain(popDocument =>
          pipe(
            popDocument,
            retrievedValidPopDocument.decode,
            TE.fromEither,
            TE.mapLeft(errors => ResponseErrorInternal(readableReport(errors))),
            TE.map(validStatusPopDocument =>
              ResponseSuccessJson(
                retrievedLollipopKeysToApiActivatedPubKey(
                  validStatusPopDocument
                )
              )
            )
          )
        )
      )
    ),
    TE.toUnion
  )();
};

export const ActivatePubKey = (
  lollipopKeysModel: LolliPOPKeysModel,
  assertionBlobService: BlobService
): express.RequestHandler => {
  const handler = ActivatePubKeyHandler(
    getPopDocumentReader(lollipopKeysModel),
    getPopDocumentWriter(lollipopKeysModel),
    getAssertionWriter(assertionBlobService)
  );

  const middlewaresWrap = withRequestMiddlewares(
    ContextMiddleware(),
    RequiredParamMiddleware("assertion_ref", AssertionRef),
    RequiredBodyPayloadMiddleware(ActivatePubKeyPayload)
  );

  return wrapRequestHandler(middlewaresWrap(handler));
};
