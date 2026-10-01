import assert from "node:assert/strict";
import { createServer } from "node:net";
import test from "node:test";
import { sendHeadRequest } from "../dist/security/http-headers.js";

test("HTTP header transport closes after headers instead of draining an unbounded body", async () => {
  const server = createServer((socket) => {
    let interval;
    socket.once("data", () => {
      socket.write("HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\nConnection: keep-alive\r\nServer: fixture\r\n\r\n");
      interval = setInterval(() => socket.write(Buffer.alloc(1024)), 1);
    });
    socket.once("close", () => clearInterval(interval));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  try {
    const response = await sendHeadRequest(
      new URL(`http://127.0.0.1:${address.port}/`),
      "127.0.0.1",
      "127.0.0.1",
    );
    assert.equal(response.status, 200);
    assert.equal(response.headers.server, "fixture");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
