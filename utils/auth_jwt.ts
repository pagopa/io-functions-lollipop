import * as jwt from "jsonwebtoken";
import * as t from "io-ts";

import * as E from "fp-ts/Either";
import * as TE from "fp-ts/TaskEither";
import { pipe } from "fp-ts/lib/function";

import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { Second } from "@pagopa/ts-commons/lib/units";

import { AssertionRef } from "../generated/definitions/internal/AssertionRef";
import { OperationId } from "../generated/definitions/internal/OperationId";

import { getGenerateJWT, getValidateJWT } from "./jwt_with_key_rotation";

import { IConfig } from "./config";

/**
 * Type Definitions
 */

// 15days = 60s * 60m * 24h * 15d
export const standardJWTTTL = 1296000 as Second;

export type AuthJWT = t.TypeOf<typeof AuthJWT>;
export const AuthJWT = t.interface({
  assertionRef: AssertionRef,
  operationId: OperationId
});

export type DecodedAuthJWT = jwt.JwtPayload & AuthJWT;

/**
 * AuthJWT Generation
 */
export type GenerateAuthGWT = (
  authJWT: AuthJWT
) => TE.TaskEither<Error, NonEmptyString>;

export const getGenerateAuthJWT = ({
  ISSUER,
  PRIMARY_PRIVATE_KEY
}: IConfig): GenerateAuthGWT =>
  pipe(
    getGenerateJWT(ISSUER, PRIMARY_PRIVATE_KEY),
    generateJWTFunction => (authJWT): ReturnType<GenerateAuthGWT> =>
      generateJWTFunction(authJWT, standardJWTTTL)
  );

/**
 * AuthJWT Validation
 */
export type ValidateAuthGWT = (
  token: NonEmptyString
) => TE.TaskEither<Error, DecodedAuthJWT>;

export const getValidateAuthJWT = ({
  ISSUER,
  PRIMARY_PUBLIC_KEY,
  SECONDARY_PUBLIC_KEY
}: IConfig): ValidateAuthGWT =>
  pipe(
    getValidateJWT(ISSUER, PRIMARY_PUBLIC_KEY, SECONDARY_PUBLIC_KEY),
    validateJWTFunction => (token): ReturnType<ValidateAuthGWT> =>
      pipe(
        validateJWTFunction(token),
        TE.chain(
          TE.fromPredicate(AuthJWT.is, () =>
            E.toError("Invalid AuthJWT payload")
          )
        )
      )
  );
