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
import { pipe, flow } from "fp-ts/lib/function";
import * as TE from "fp-ts/lib/TaskEither";
import { toCosmosErrorResponse } from "@pagopa/io-functions-commons/dist/src/utils/cosmosdb_model";
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
  const prefix = AssertionRefSha256.is(assertion_ref)
    ? JwkPubKeyHashAlgorithmEnum.sha256
    : AssertionRefSha384.is(assertion_ref)
    ? JwkPubKeyHashAlgorithmEnum.sha384
    : JwkPubKeyHashAlgorithmEnum.sha512;

  return pipe(
    errorOrAssertionFileName,
    TE.fromEither,
    TE.mapLeft(errors =>
      ResponseErrorInternal(
        `Could not decode assertion file name | ${readableReport(errors)}`
      )
    ),
    TE.chain(assertionFileName =>
      pipe(
        AssertionWriter(assertionFileName, body.assertion),
        TE.mapLeft(error =>
          ResponseErrorInternal(`storeAssertion failed | ${error.detail}`)
        ),
        TE.chainW(() =>
          pipe(
            PopDocumentReader(assertion_ref),
            TE.mapLeft(error =>
              ResponseErrorInternal(`PopDocument read failed | ${error.kind}`)
            ),
            // retrieve pubkey here (JWK ENCODED)
            TE.chain(({ pubKey }) =>
              pipe(
                prefix,
                TE.fromPredicate(
                  prefix => prefix !== JwkPubKeyHashAlgorithmEnum.sha512,
                  () => false
                ),
                TE.fold(
                  () =>
                    pipe(
                      PopDocumentWriter({
                        pubKey,
                        assertionFileName,
                        assertionType: body.assertion_type,
                        assertionRef: assertion_ref,
                        expiredAt: body.expires_at,
                        fiscalCode: body.fiscal_code,
                        status: PubKeyStatusEnum.VALID,
                        ttl: TTL_VALUE_AFTER_UPDATE
                      }),
                      TE.mapLeft(error => ResponseErrorInternal(error.kind))
                    ),
                  () => {
                    const errorOrMasterKey = pipe(
                      pubKey,
                      JwkPublicKeyFromToken.decode,
                      TE.fromEither,
                      TE.chainW(jwkPublicKey =>
                        calculateThumbprint(jwkPublicKey, prefix)
                      ),
                      TE.mapLeft(error =>
                        error instanceof Error
                          ? ResponseErrorInternal(error.message)
                          : ResponseErrorInternal(readableReport(error))
                      ),
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
                      TE.chainW(masterKey =>
                        PopDocumentWriter({
                          pubKey,
                          ttl: TTL_VALUE_AFTER_UPDATE,
                          assertionRef: masterKey,
                          assertionFileName,
                          status: PubKeyStatusEnum.VALID,
                          assertionType: body.assertion_type,
                          fiscalCode: body.fiscal_code,
                          expiredAt: body.expires_at
                        })
                      ),
                      TE.chainW(() =>
                        PopDocumentWriter({
                          pubKey,
                          assertionFileName,
                          assertionType: body.assertion_type,
                          assertionRef: assertion_ref,
                          expiredAt: body.expires_at,
                          fiscalCode: body.fiscal_code,
                          status: PubKeyStatusEnum.VALID,
                          ttl: TTL_VALUE_AFTER_UPDATE
                        })
                      ),
                      TE.mapLeft(error => ResponseErrorInternal(error.kind))
                    );
                  }
                ),
                //here we return the popDocument wrapped in an IResponseSuccessJson
                TE.chain(
                  flow(
                    retrievedValidPopDocument.decode,
                    TE.fromEither,
                    TE.map(validStatusPopDocument =>
                      ResponseSuccessJson(
                        retrievedLollipopKeysToApiActivatedPubKey(
                          validStatusPopDocument
                        )
                      )
                    ),
                    TE.mapLeft(_ =>
                      ResponseErrorInternal(
                        // Before we did an upsert with status VALID, so it is
                        // unexpected to have received a status !== VALID
                        "Unexpected retrieved popDocument status"
                      )
                    )
                  )
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
