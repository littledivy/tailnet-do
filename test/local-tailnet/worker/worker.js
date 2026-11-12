// Runs examples/https-node unchanged against the local fake tailnet. The
// only addition: the fake DERP relay speaks plain HTTP, which Tailscale
// enables with an environment variable in the Go process.
import "../../../src/wasm_exec.js";
import worker, { HttpsNode } from "../../../examples/https-node/src/index.js";

const RealGo = globalThis.Go;
globalThis.Go = class extends RealGo {
  constructor() {
    super();
    this.env.TS_DEBUG_USE_DERP_HTTP = "1";
  }
};

export { HttpsNode };
export default worker;
