// The management-plane DPoP Connect interceptor (seam-sdk#290). Internal: `index.ts` does not re-export
// this module; `SeamAdminClient.connect({ dpopKey })` installs it.

import type { Interceptor } from "@connectrpc/connect";
import { toBinary } from "@bufbuild/protobuf";

import { DpopError, type OperatorDpopKey, mgmtDpopGrpcHtu, mgmtDpopProof } from "./dpop.js";

/** The one message of a unary-input call (unary, or server-streaming like `StreamEvents`), and an
 * iterable that replays it. No management RPC is client-streaming, so any other count is a bug. */
export async function onlyMessage<T>(messages: AsyncIterable<T>): Promise<T> {
  let only: T | undefined;
  let count = 0;
  for await (const m of messages) {
    only = m;
    count += 1;
    if (count > 1) break;
  }
  if (count !== 1) {
    throw new DpopError(`a management call must carry exactly one request message (got ${count > 1 ? "more than one" : "none"})`);
  }
  return only as T;
}

async function* replay<T>(message: T): AsyncIterable<T> {
  yield message;
}

/** A Connect interceptor that attaches `authorization: DPoP <token>` and a fresh `dpop` proof to every
 * request (seam-sdk#290). The proof is signed per call — Connect runs interceptors per call, so a retry
 * is re-signed too — over the exact protobuf bytes of the request message. */
export function dpopAuth(
  token: string,
  key: OperatorDpopKey,
  aud: string,
  clock: (() => number) | undefined,
): Interceptor {
  const sign = (method: string, body: Uint8Array) =>
    mgmtDpopProof(key, token, {
      htm: "POST",
      htu: mgmtDpopGrpcHtu(method, aud),
      body,
      ...(clock === undefined ? {} : { iat: clock() }),
    });
  return (next) => async (req) => {
    const method = `/${req.method.parent.typeName}/${req.method.name}`;
    req.header.set("authorization", `DPoP ${token}`);
    if (!req.stream) {
      req.header.set("dpop", sign(method, toBinary(req.method.input, req.message)));
      return next(req);
    }
    const message = await onlyMessage(req.message);
    req.header.set("dpop", sign(method, toBinary(req.method.input, message)));
    return next({ ...req, message: replay(message) });
  };
}
