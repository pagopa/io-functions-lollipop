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
import { ActivatedPubKey } from "../generated/definitions/internal/ActivatedPubKey";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import { ActivatePubKeyPayload } from "../generated/definitions/internal/ActivatePubKeyPayload";
import {
  AssertionWriter,
  getAssertionWriter,
  getPopDocumentWriter,
  PopDocumentWriter
} from "../utils/writers";
import { pipe } from "fp-ts/lib/function";
import * as TE from "fp-ts/lib/TaskEither";
import { getPopDocumentReader, PopDocumentReader } from "../utils/readers";
import { toCosmosErrorResponse } from "@pagopa/io-functions-commons/dist/src/utils/cosmosdb_model";
import { AssertionRefSha256 } from "../generated/definitions/internal/AssertionRefSha256";
import * as jose from "jose";
import { AssertionRefSha384 } from "../generated/definitions/internal/AssertionRefSha384";
import { JwkPubKeyHashAlgorithmEnum } from "../generated/definitions/internal/JwkPubKeyHashAlgorithm";
import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";

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

const calculateThumbprint = (
  jwkPubKey: jose.JWK
): TE.TaskEither<Error, string> =>
  TE.tryCatch(
    () => jose.calculateJwkThumbprint(jwkPubKey),
    err => new Error(`Can not calculate JwkThumbprint | ${err}`)
  );

const getJoseJwk = (jwkPubKey: JwkPublicKey): TE.TaskEither<Error, jose.JWK> =>
  pipe(
    TE.tryCatch(
      () => jose.importJWK(jwkPubKey),
      err => new Error(`Can not import Jwk | ${err}`)
    ),
    TE.chain(joseKey =>
      TE.tryCatch(
        () => jose.exportJWK(joseKey),
        err => new Error(`Can not export Jwk | ${err}`)
      )
    )
  );

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

  const assertionFileName = `${body.fiscal_code}-${assertion_ref}`;
  const prefix = AssertionRefSha256.is(assertion_ref)
    ? JwkPubKeyHashAlgorithmEnum.sha256
    : AssertionRefSha384.is(assertion_ref)
    ? JwkPubKeyHashAlgorithmEnum.sha384
    : JwkPubKeyHashAlgorithmEnum.sha512;

  return pipe(
    AssertionWriter(assertionFileName, body.assertion),
    TE.mapLeft(_ => ResponseErrorInternal("storeAssertion failed")),
    TE.chainW(() =>
      pipe(
        PopDocumentReader(assertion_ref),
        TE.mapLeft(error =>
          ResponseErrorInternal(toCosmosErrorResponse(error).kind)
        ),
        // retrieve pubkey here (JWK ENCODED)
        TE.chain(({ pubKey }) =>
          pipe(
            //Write predefined user assertion_ref
            PopDocumentWriter(assertion_ref),
            TE.mapLeft(error =>
              ResponseErrorInternal(toCosmosErrorResponse(error).kind)
            ),
            // if prefix wasn't sha512 we write a
            // popDocument with a masterkey generated
            TE.chainW(retrievedPopDocument =>
              pipe(
                prefix,
                TE.fromPredicate(
                  prefix => prefix !== JwkPubKeyHashAlgorithmEnum.sha512,
                  () => false
                ),
                TE.fold(
                  // if prefix was already sha512 we must return the first retrievedPopDocument
                  () => TE.right(ResponseSuccessJson(retrievedPopDocument)),
                  () => {
                    const errorOrMasterKey = pipe(
                      pubKey,
                      TE.of,
                      TE.chainW(getJoseJwk),
                      TE.chainW(calculateThumbprint),
                      TE.mapLeft(error => ResponseErrorInternal(error.message)),
                      TE.map(
                        thumbprint =>
                          `${JwkPubKeyHashAlgorithmEnum.sha512}-${thumbprint}`
                      ),
                      TE.chainW(createdAssertionRef =>
                        TE.fromEither(AssertionRef.decode(createdAssertionRef))
                      ),
                      TE.mapLeft(_ =>
                        ResponseErrorInternal(`Can not decode to assertionRef`)
                      )
                    );
                    return pipe(
                      errorOrMasterKey,
                      TE.chainW(PopDocumentWriter),
                      TE.map(res => ResponseSuccessJson(res)),
                      TE.mapLeft(error =>
                        ResponseErrorInternal(toCosmosErrorResponse(error).kind)
                      )
                    );
                  }
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
  COSMOS_MODEL: any,
  BLOB_STORAGE: any
): express.RequestHandler => {
  const handler = ActivatePubKeyHandler(
    getPopDocumentReader(COSMOS_MODEL),
    getPopDocumentWriter(COSMOS_MODEL),
    getAssertionWriter(BLOB_STORAGE)
  );

  const middlewaresWrap = withRequestMiddlewares(
    ContextMiddleware(),
    // AzureApiAuthMiddleware(new Set([ApiLollipopAssertionRead])),
    RequiredParamMiddleware("assertion_ref", AssertionRef),
    RequiredBodyPayloadMiddleware(ActivatePubKeyPayload)
  );

  return wrapRequestHandler(middlewaresWrap(handler));
};
