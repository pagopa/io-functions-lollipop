/* eslint-disable no-console */
/* eslint-disable max-params */
import { Context } from "@azure/functions";
import { constVoid, flow, pipe } from "fp-ts/lib/function";
import * as TE from "fp-ts/TaskEither";
import * as E from "fp-ts/Either";
import * as RA from "fp-ts/ReadonlyArray";
import * as B from "fp-ts/boolean";
import * as O from "fp-ts/Option";
import { RevokeAssertionRefInfo } from "@pagopa/io-functions-commons/dist/src/entities/revoke_assertion_ref_info";
import * as jose from "jose";
import { JwkPublicKeyFromToken } from "@pagopa/ts-commons/lib/jwk";
import { TelemetryClient, trackException } from "../utils/appinsights";
import { errorsToError } from "../utils/conversions";
import {
  Failure,
  PermanentFailure,
  toPermanentFailure,
  toTransientFailure,
  TransientFailure
} from "../utils/errors";
import {
  LolliPOPKeysModel,
  NotPendingLolliPopPubKeys
} from "../model/lollipop_keys";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import { AssertionRefSha512 } from "../generated/definitions/internal/AssertionRefSha512";
import { PubKeyStatusEnum } from "../generated/definitions/internal/PubKeyStatus";
import { JwkPubKeyHashAlgorithm } from "../generated/definitions/internal/JwkPubKeyHashAlgorithm";

/**
 * Based on a previous retrieved LollipopPubKey that match with assertionRef retrieved on queue
 * this function extracts all lollipopPubKeys to be revoked including master key
 *
 * @param lollipopKeysModel
 * @returns a readonly array of lollipopPubKeys to be revoked
 */
const extractPubKeysToRevoke = (
  lollipopKeysModel: LolliPOPKeysModel,
  masterAlgo: JwkPubKeyHashAlgorithm
) => (
  notPendingLollipopPubKeys: NotPendingLolliPopPubKeys
): TE.TaskEither<Failure, ReadonlyArray<NotPendingLolliPopPubKeys>> =>
  pipe(
    notPendingLollipopPubKeys.assertionRef,
    AssertionRefSha512.is,
    B.fold(
      () =>
        pipe(
          notPendingLollipopPubKeys.pubKey,
          JwkPublicKeyFromToken.decode,
          TE.fromEither,
          TE.mapLeft(() =>
            toPermanentFailure(Error("Cannot decode stored jwk"))()
          ),
          TE.chain(jwkPublicKey =>
            pipe(
              TE.tryCatch(
                () => jose.calculateJwkThumbprint(jwkPublicKey, masterAlgo),
                flow(E.toError, err =>
                  toPermanentFailure(
                    Error(
                      `Cannot calculate master key jwk's thumbprint|${err.message}`
                    )
                  )()
                )
              ),
              TE.chainEitherK(
                flow(
                  thumbprint => `${masterAlgo}-${thumbprint}`,
                  AssertionRef.decode,
                  E.mapLeft(() =>
                    toPermanentFailure(
                      Error("Cannot decode master AssertionRef")
                    )()
                  )
                )
              ),
              TE.chainW(masterAssertionRef =>
                pipe(
                  lollipopKeysModel.findLastVersionByModelId([
                    masterAssertionRef
                  ]),
                  TE.mapLeft(_ =>
                    toTransientFailure(
                      Error("Cannot perform find masterKey on CosmosDB")
                    )()
                  )
                )
              ),
              TE.chain(
                TE.fromOption(() =>
                  toTransientFailure(
                    Error("Cannot find a master lollipopPubKey")
                  )()
                )
              ),
              TE.chainEitherKW(
                flow(
                  NotPendingLolliPopPubKeys.decode,
                  E.mapLeft(_ =>
                    toPermanentFailure(
                      Error("Cannot decode a VALID master lollipopPubKey")
                    )()
                  )
                )
              ),
              TE.map(validMasterLollipopPubKeys => [
                validMasterLollipopPubKeys,
                notPendingLollipopPubKeys
              ])
            )
          )
        ),
      () => TE.of([notPendingLollipopPubKeys])
    )
  );

export const handleRevoke = (
  context: Context,
  telemetryClient: TelemetryClient,
  lollipopKeysModel: LolliPOPKeysModel,
  masterAlgo: JwkPubKeyHashAlgorithm,
  rawRevokeMessage: unknown
): Promise<Failure | void> =>
  pipe(
    rawRevokeMessage,
    RevokeAssertionRefInfo.decode,
    TE.fromEither,
    TE.mapLeft(flow(errorsToError, e => toPermanentFailure(e)())),
    TE.chain(revokeAssertionRefInfo =>
      pipe(
        lollipopKeysModel.findLastVersionByModelId([
          revokeAssertionRefInfo.assertion_ref
        ]),
        TE.mapLeft(_ =>
          toTransientFailure(Error("Cannot perform find on CosmosDB"))()
        ),
        TE.map(O.chainEitherK(NotPendingLolliPopPubKeys.decode)),
        TE.chain(
          O.foldW(
            () => TE.right(void 0),
            flow(
              extractPubKeysToRevoke(lollipopKeysModel, masterAlgo),
              TE.chainW(
                flow(
                  RA.map(lollipopKey =>
                    lollipopKeysModel.upsert({
                      ...lollipopKey,
                      status: PubKeyStatusEnum.REVOKED
                    })
                  ),
                  RA.sequence(TE.ApplicativeSeq),
                  TE.mapLeft(_ =>
                    toTransientFailure(
                      Error("Cannot perform upsert CosmosDB")
                    )()
                  )
                )
              )
            )
          )
        ),
        TE.map(constVoid)
      )
    ),
    TE.mapLeft(err => {
      const isTransient = TransientFailure.is(err);
      const error = isTransient
        ? `HandlePubKeyRevoke|TRANSIENT_ERROR=${err.reason}`
        : `HandlePubKeyRevoke|FATAL|PERMANENT_ERROR=${
            err.reason
          }|INPUT=${JSON.stringify(rawRevokeMessage)}`;
      trackException(telemetryClient, {
        exception: new Error(error),
        properties: {
          detail: err.kind,
          errorMessage: error,
          fatal: PermanentFailure.is(err).toString(),
          isSuccess: "false",
          modelId: err.modelId ?? "",
          name: "lollipop.pubKeys.revoke.failure"
        },
        tagOverrides: { samplingEnabled: String(isTransient) }
      });
      context.log.error(error);
      if (isTransient) {
        // Trigger a retry in case of temporary failures
        throw new Error(error);
      }
      return err;
    }),
    TE.map(constVoid),
    TE.toUnion
  )();