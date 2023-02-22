import * as TE from "fp-ts/TaskEither";
import * as E from "fp-ts/Either";
import * as B from "fp-ts/boolean";
import { flow, pipe } from "fp-ts/lib/function";
import { JwkPublicKeyFromToken } from "@pagopa/ts-commons/lib/jwk";
import * as jose from "jose";
import * as t from "io-ts";
import { LolliPopPubKeys } from "../model/lollipop_keys";
import {
  JwkPubKeyHashAlgorithm,
  JwkPubKeyHashAlgorithmEnum
} from "../generated/definitions/internal/JwkPubKeyHashAlgorithm";
import { AssertionRefSha512 } from "../generated/definitions/internal/AssertionRefSha512";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import { AssertionRefSha384 } from "../generated/definitions/internal/AssertionRefSha384";
import { AssertionRefSha256 } from "../generated/definitions/internal/AssertionRefSha256";
import { assertNever } from "./errors";

export const AssertionsRef = t.intersection([
  t.type({
    master: AssertionRef
  }),
  t.partial({
    used: AssertionRef
  })
]);

export type AssertionsRef = t.TypeOf<typeof AssertionsRef>;

const getMasterAssertionRefType = (
  masterAlgo: JwkPubKeyHashAlgorithm
): typeof AssertionRef.types[number] => {
  switch (masterAlgo) {
    case JwkPubKeyHashAlgorithmEnum.sha512:
      return AssertionRefSha512;
    case JwkPubKeyHashAlgorithmEnum.sha384:
      return AssertionRefSha384;
    case JwkPubKeyHashAlgorithmEnum.sha256:
      return AssertionRefSha256;
    default:
      return assertNever(masterAlgo);
  }
};

/**
 * Return all assertionsRef related to a given used pubKey
 */
export const getAllAssertionsRef = (
  masterAlgo: JwkPubKeyHashAlgorithm,
  usedLollipopPubKeys: LolliPopPubKeys
): TE.TaskEither<Error, AssertionsRef> =>
  pipe(
    usedLollipopPubKeys.assertionRef,
    getMasterAssertionRefType(masterAlgo).is,
    B.fold(
      () =>
        pipe(
          usedLollipopPubKeys.pubKey,
          JwkPublicKeyFromToken.decode,
          TE.fromEither,
          TE.mapLeft(() => Error("Cannot decode used jwk")),

          TE.chain(jwkPublicKey =>
            pipe(
              TE.tryCatch(
                () => jose.calculateJwkThumbprint(jwkPublicKey, masterAlgo),
                flow(E.toError, err =>
                  Error(
                    `Cannot calculate master key jwk's thumbprint|${err.message}`
                  )
                )
              ),
              TE.chainEitherK(
                flow(
                  thumbprint => `${masterAlgo}-${thumbprint}`,
                  AssertionRef.decode,
                  E.mapLeft(() => Error("Cannot decode master AssertionRef"))
                )
              )
            )
          ),
          TE.map(validMasterLollipopPubKeyAssertionRef => ({
            master: validMasterLollipopPubKeyAssertionRef,
            used: usedLollipopPubKeys.assertionRef
          }))
        ),
      () => TE.of({ master: usedLollipopPubKeys.assertionRef })
    )
  );
