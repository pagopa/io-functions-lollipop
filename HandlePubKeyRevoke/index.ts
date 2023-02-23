import { AzureFunction, Context } from "@azure/functions";
import { JwkPubKeyHashAlgorithmEnum } from "../generated/definitions/internal/JwkPubKeyHashAlgorithm";
import {
  LolliPOPKeysModel,
  LOLLIPOPKEYS_COLLECTION_NAME
} from "../model/lollipop_keys";
import { initTelemetryClient } from "../utils/appinsights";
import { getConfigOrThrow } from "../utils/config";
import { cosmosdbInstance } from "../utils/cosmosdb";
import { Failure } from "../utils/errors";
import { handleRevoke } from "./handler";

const config = getConfigOrThrow();

const lollipopKeysModel = new LolliPOPKeysModel(
  cosmosdbInstance.container(LOLLIPOPKEYS_COLLECTION_NAME)
);

const telemetryClient = initTelemetryClient(
  config.APPINSIGHTS_INSTRUMENTATIONKEY
);

const masterAlgo = JwkPubKeyHashAlgorithmEnum.sha512;

export const index: AzureFunction = (
  context: Context,
  rawRevokeMessage: unknown
): Promise<Failure | void> =>
  handleRevoke(
    context,
    telemetryClient,
    lollipopKeysModel,
    masterAlgo,
    rawRevokeMessage
  );

export default index;
