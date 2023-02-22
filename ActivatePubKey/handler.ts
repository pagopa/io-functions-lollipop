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
  ResponseSuccessJson
} from "@pagopa/ts-commons/lib/responses";
import * as express from "express";
import { pipe } from "fp-ts/lib/function";
import * as TE from "fp-ts/lib/TaskEither";
import * as O from "fp-ts/lib/Option";
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
import { JwkPubKeyHashAlgorithmEnum } from "../generated/definitions/internal/JwkPubKeyHashAlgorithm";
import {
  AssertionFileName,
  TTL_VALUE_AFTER_UPDATE
} from "../model/lollipop_keys";
import { PubKeyStatusEnum } from "../generated/definitions/internal/PubKeyStatus";
import {
  retrievedLollipopKeysToApiActivatedPubKey,
  retrievedValidPopDocument
} from "../utils/lollipop_keys_utils";
import { getAllAssertionsRef } from "../utils/lollipopKeys";
import { domainErrorToResponseError } from "../utils/domain_errors";

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
): ActivatePubKeyHandler => (_, assertion_ref, body) =>
  pipe(
    popDocumentReader(assertion_ref),
    TE.mapLeft(domainErrorToResponseError),
    TE.chainW(popDocument =>
      pipe(
        `${body.fiscal_code}-${assertion_ref}`,
        AssertionFileName.decode,
        TE.fromEither,
        TE.bindTo("assertionFileName"),
        TE.mapLeft(errors =>
          ResponseErrorInternal(
            `Could not decode assertionFileName | ${readableReport(errors)}`
          )
        ),
        TE.chainFirst(({ assertionFileName }) =>
          pipe(
            assertionWriter(assertionFileName, body.assertion),
            TE.mapLeft(error => ResponseErrorInternal(error.detail))
          )
        ),
        TE.bind("assertionRefs", () =>
          pipe(
            getAllAssertionsRef(JwkPubKeyHashAlgorithmEnum.sha512, popDocument),
            TE.mapLeft((error: Error) => ResponseErrorInternal(error.message))
          )
        ),
        TE.bind(
          "retrievedPopDocument",
          ({ assertionRefs, assertionFileName }) =>
            pipe(
              popDocumentWriter({
                pubKey: popDocument.pubKey,
                ttl: TTL_VALUE_AFTER_UPDATE,
                assertionRef: assertionRefs.master,
                assertionFileName,
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
              TE.fromNullable(() => void 0),
              TE.foldW(
                () => TE.right(void 0),
                u =>
                  pipe(
                    popDocumentWriter({
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
        TE.chain(({ retrievedPopDocument, retrievedUsedPopDocument }) =>
          pipe(
            retrievedUsedPopDocument,
            O.fromNullable,
            O.getOrElse(() => retrievedPopDocument),
            retrievedValidPopDocument.decode,
            TE.fromEither,
            TE.mapLeft(errors =>
              ResponseErrorInternal(
                `Could not decode retrievedPopDocument | ${readableReport(
                  errors
                )}`
              )
            ),
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
