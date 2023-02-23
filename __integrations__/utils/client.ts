export const ACTIVATE_PUB_KEY_PATH = "api/v1/pubkeys";
export const fetchActivatePubKey = (
  assertionRef: string,
  body: unknown,
  baseUrl: string
) =>
  fetch(`${baseUrl}/${ACTIVATE_PUB_KEY_PATH}/${assertionRef}`, {
    method: "PUT",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
