import { ActivatedPubKey } from "../generated/definitions/internal/ActivatedPubKey";
import { Ttl, ValidLolliPopPubKeys } from "../model/lollipop_keys";
import * as t from "io-ts";
import { RetrievedVersionedModelTTL } from "@pagopa/io-functions-commons/dist/src/utils/cosmosdb_model_versioned_ttl";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";

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
  assertion_ref: popDocument.assertionRef,
  assertion_file_name: (popDocument.assertionFileName as unknown) as NonEmptyString,
  assertion_type: popDocument.assertionType,
  version: popDocument.version,
  status: popDocument.status,
  pub_key: popDocument.pubKey,
  fiscal_code: popDocument.fiscalCode,
  expires_at: popDocument.expiredAt,
  ttl: popDocument.ttl
});
