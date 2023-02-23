import * as TE from "fp-ts/TaskEither";
import * as E from "fp-ts/Either";
import * as B from "fp-ts/boolean";
import * as O from "fp-ts/Option";
import { flow, pipe } from "fp-ts/lib/function";
import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";
import * as t from "io-ts";
import {
  JwkPubKeyHashAlgorithm,
  JwkPubKeyHashAlgorithmEnum
} from "../generated/definitions/internal/JwkPubKeyHashAlgorithm";
import { AssertionRefSha512 } from "../generated/definitions/internal/AssertionRefSha512";
import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import { AssertionRefSha384 } from "../generated/definitions/internal/AssertionRefSha384";
import { AssertionRefSha256 } from "../generated/definitions/internal/AssertionRefSha256";
import { assertNever } from "./errors";
import { calculateThumbprint } from "./thumbprint";
import { Ttl, ValidLolliPopPubKeys } from "../model/lollipop_keys";
import { RetrievedVersionedModelTTL } from "@pagopa/io-functions-commons/dist/src/utils/cosmosdb_model_versioned_ttl";
import { ActivatedPubKey } from "../generated/definitions/internal/ActivatedPubKey";

export const MASTER_HASH_ALGO = JwkPubKeyHashAlgorithmEnum.sha512;
export const AssertionRefByType = t.intersection([
  t.type({
    master: AssertionRef
  }),
  t.partial({
    used: AssertionRef
  })
]);

export type AssertionRefByType = t.TypeOf<typeof AssertionRefByType>;

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

export const calculateAssertionRef = (algo: JwkPubKeyHashAlgorithm) => (
  jwkPublicKey: JwkPublicKey
): TE.TaskEither<Error, AssertionRef> =>
  pipe(
    jwkPublicKey,
    calculateThumbprint(algo),
    TE.chainEitherK(
      flow(
        thumbprint => `${algo}-${thumbprint}`,
        AssertionRef.decode,
        E.mapLeft(() => Error("Cannot decode master AssertionRef"))
      )
    )
  );

export const algoToAssertionRefSet = new Set([
  { algo: JwkPubKeyHashAlgorithmEnum.sha256, type: AssertionRefSha256 },
  { algo: JwkPubKeyHashAlgorithmEnum.sha384, type: AssertionRefSha384 },
  { algo: JwkPubKeyHashAlgorithmEnum.sha512, type: AssertionRefSha512 }
]);

export const getAlgoFromAssertionRef = (
  assertionRef: AssertionRef
): JwkPubKeyHashAlgorithm =>
  pipe(
    Array.from(algoToAssertionRefSet),
    ar => ar.find(entry => entry.type.is(assertionRef)),
    O.fromNullable,
    O.map(pubKeyHashAlgo => pubKeyHashAlgo.algo),
    O.getOrElseW(() => void 0 as never)
  );

/**
 * Return all assertionsRef related to a given used pubKey
 */
export const getAllAssertionsRef = (
  masterAlgo: JwkPubKeyHashAlgorithm,
  usedAlgo: JwkPubKeyHashAlgorithm,
  jwkPubKey: JwkPublicKey
): TE.TaskEither<Error, AssertionRefByType> =>
  pipe(
    jwkPubKey,
    calculateAssertionRef(usedAlgo),
    TE.chain(usedAssertionRef =>
      pipe(
        usedAssertionRef,
        getMasterAssertionRefType(masterAlgo).is,
        B.fold(
          () =>
            pipe(
              jwkPubKey,
              calculateAssertionRef(masterAlgo),
              TE.map(validMasterLollipopPubKeyAssertionRef => ({
                master: validMasterLollipopPubKeyAssertionRef,
                used: usedAssertionRef
              }))
            ),
          () => TE.of({ master: usedAssertionRef })
        )
      )
    )
  );

export const retrievedValidPopDocument = t.intersection([
  ValidLolliPopPubKeys,
  Ttl,
  RetrievedVersionedModelTTL
]);
export type RetrievedValidPopDocument = t.TypeOf<
  typeof retrievedValidPopDocument
>;

export const retrievedLollipopKeysToApiActivatedPubKey = (
  popDocument: RetrievedValidPopDocument
): ActivatedPubKey => ({
  assertion_file_name: (popDocument.assertionFileName as unknown) as NonEmptyString,
  assertion_ref: popDocument.assertionRef,
  assertion_type: popDocument.assertionType,
  expires_at: popDocument.expiredAt,
  fiscal_code: popDocument.fiscalCode,
  pub_key: popDocument.pubKey,
  status: popDocument.status,
  ttl: popDocument.ttl,
  version: popDocument.version
});
