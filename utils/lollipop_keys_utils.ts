import * as TE from "fp-ts/lib/TaskEither";
import * as t from "io-ts";
import * as jose from "jose";
import { RetrievedVersionedModelTTL } from "@pagopa/io-functions-commons/dist/src/utils/cosmosdb_model_versioned_ttl";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";
import { Ttl, ValidLolliPopPubKeys } from "../model/lollipop_keys";
import { ActivatedPubKey } from "../generated/definitions/internal/ActivatedPubKey";
import { JwkPubKeyHashAlgorithmEnum } from "../generated/definitions/internal/JwkPubKeyHashAlgorithm";

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

export const calculateThumbprint = (
  jwkPubKey: JwkPublicKey,
  prefix: JwkPubKeyHashAlgorithmEnum
): TE.TaskEither<Error, string> =>
  TE.tryCatch(
    () => jose.calculateJwkThumbprint(jwkPubKey, prefix),
    err => new Error(`Can not calculate JwkThumbprint | ${err}`)
  );
