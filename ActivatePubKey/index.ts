import { AzureFunction, Context } from "@azure/functions";
import * as express from "express";
import { secureExpressApp } from "@pagopa/io-functions-commons/dist/src/utils/express";
import { setAppContext } from "@pagopa/io-functions-commons/dist/src/utils/middlewares/context_middleware";
import createAzureFunctionHandler from "@pagopa/express-azure-functions/dist/src/createAzureFunctionsHandler";
import { createBlobService } from "azure-storage";
import {
  LolliPOPKeysModel,
  LOLLIPOPKEYS_COLLECTION_NAME
} from "../model/lollipop_keys";
import { cosmosdbInstance } from "../utils/cosmosdb";
import { getConfigOrThrow } from "../utils/config";
import { getPopDocumentReader } from "../utils/readers";
import { getAssertionWriter, getPopDocumentWriter } from "../utils/writers";
import { ActivatePubKey } from "./handler";

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
  "/api/v1/pubKeys/:assertion_ref",
  ActivatePubKey(
    getPopDocumentReader(lollipopKeysModel),
    getPopDocumentWriter(lollipopKeysModel),
    getAssertionWriter(
      assertionBlobService,
      config.LOLLIPOP_ASSERTION_STORAGE_CONTAINER_NAME
    )
  )
);

const azureFunctionHandler = createAzureFunctionHandler(app);

const httpStart: AzureFunction = (context: Context): void => {
  setAppContext(app, context);
  azureFunctionHandler(context);
};

export default httpStart;
