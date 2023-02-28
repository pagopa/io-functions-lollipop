import { getNodeFetch } from "./fetch";

export const ACTIVATE_PUB_KEY_PATH = "api/v1/pubkeys";
export const fetchActivatePubKey = (
  assertionRef: string,
  body: unknown,
  baseUrl: string,
  nodeFetch: typeof fetch
) =>
  nodeFetch(`${baseUrl}/${ACTIVATE_PUB_KEY_PATH}/${assertionRef}`, {
    method: "PUT",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

export const RESERVE_PUB_KEY_PATH = "api/v1/pubkeys";
export const fetchReservePubKey = (
  body: unknown,
  baseUrl: string,
  nodeFetch: typeof fetch
) =>
  nodeFetch(`${baseUrl}/${RESERVE_PUB_KEY_PATH}`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
