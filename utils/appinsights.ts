import * as ai from "applicationinsights";
import { initAppInsights } from "@pagopa/ts-commons/lib/appinsights";
import * as O from "fp-ts/lib/Option";
import { pipe } from "fp-ts/lib/function";
import {
  EventTelemetry,
  ExceptionTelemetry
} from "applicationinsights/out/Declarations/Contracts";
import { AppInsightsConfig } from "./config";

// the internal function runtime has MaxTelemetryItem per second set to 20 by default
// @see https://github.com/Azure/azure-functions-host/blob/master/src/WebJobs.Script/Config/ApplicationInsightsLoggerOptionsSetup.cs#L29
const DEFAULT_SAMPLING_PERCENTAGE = 5;

// Avoid to initialize Application Insights more than once
// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
export const initTelemetryClient = (config: AppInsightsConfig) =>
  pipe(
    ai.defaultClient,
    O.fromNullable,
    O.getOrElse(() => {
      const client = initAppInsights(config.APPINSIGHTS_CONNECTION_STRING, {
        cloudRole: config.APPINSIGHTS_CLOUD_ROLE_NAME,
        disableAppInsights: config.APPINSIGHTS_DISABLE === "true",
        samplingPercentage: pipe(
          config.APPINSIGHTS_SAMPLING_PERCENTAGE,
          O.fromNullable,
          O.getOrElse(() => DEFAULT_SAMPLING_PERCENTAGE)
        )
      });
      // eslint-disable-next-line functional/immutable-data
      client.config.correlationHeaderExcludedDomains =
        config.APPINSIGHTS_EXCLUDED_DOMAINS || [];
      return client;
    })
  );

export type TelemetryClient = ReturnType<typeof initTelemetryClient>;

export const trackEvent = (
  telemetryClient: TelemetryClient,
  event: EventTelemetry
): void => {
  pipe(
    O.fromNullable(telemetryClient),
    O.map(client => O.tryCatch(() => client.trackEvent(event)))
  );
};

export const trackException = (
  telemetryClient: TelemetryClient,
  event: ExceptionTelemetry
): void => {
  pipe(
    O.fromNullable(telemetryClient),
    O.map(client => O.tryCatch(() => client.trackException(event)))
  );
};
