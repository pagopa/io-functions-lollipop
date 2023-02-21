import { AzureFunction, Context } from "@azure/functions";
import * as express from "express";
import { secureExpressApp } from "@pagopa/io-functions-commons/dist/src/utils/express";
import { setAppContext } from "@pagopa/io-functions-commons/dist/src/utils/middlewares/context_middleware";
import createAzureFunctionHandler from "@pagopa/express-azure-functions/dist/src/createAzureFunctionsHandler";
import { ActivatePubKey } from "./handler";
import {
  LolliPOPKeysModel,
  LOLLIPOPKEYS_COLLECTION_NAME
} from "../model/lollipop_keys";
import { cosmosdbInstance } from "../utils/cosmosdb";
import { createBlobService } from "azure-storage";
import { getConfigOrThrow } from "../utils/config";

const config = getConfigOrThrow();

// Setup Express
const app = express();
secureExpressApp(app);

const lollipopKeysModel = new LolliPOPKeysModel(
  cosmosdbInstance.container(LOLLIPOPKEYS_COLLECTION_NAME)
);

const assertionBlobService = createBlobService(
  config.LOLLIPOP_ASSERTION_STORAGE_CONNECTION_STRING
);

// Add express route
app.put(
  "/pubKeys/:assertion_ref",
  ActivatePubKey(lollipopKeysModel, assertionBlobService)
);

const azureFunctionHandler = createAzureFunctionHandler(app);

const httpStart: AzureFunction = (context: Context): void => {
  setAppContext(app, context);
  azureFunctionHandler(context);
};

export default httpStart;
