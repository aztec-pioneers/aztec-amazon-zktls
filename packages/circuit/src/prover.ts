// Stateful wrapper around noir_js + bb.js. Keeps the Noir executor and the
// UltraHonk backend alive across proofs so callers don't pay init cost per
// call. bb.js 3.x split the backend into a long-lived `Barretenberg` API
// instance plus a thin `UltraHonkBackend` wrapper that takes bytecode + api.
//
// Caller picks the runtime profile via `ProverInit`:
//   - Browser: pass `threads` (e.g. navigator.hardwareConcurrency); bb.js
//     auto-selects WasmWorker. The page must be cross-origin-isolated
//     (COEP/COOP headers) for the worker pool to use SharedArrayBuffer.
//   - Node:    pass `backend: BackendType.Wasm` to skip the default
//     NativeUnixSocket path (which spawns a `bb` subprocess and races
//     under vitest).

import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import {
  Barretenberg,
  BackendType,
  UltraHonkBackend,
  type ProofData,
} from "@aztec/bb.js";
import type { AnyCircuitInputs } from "./types.js";

export { Barretenberg };

export interface ProverInit {
  circuit: CompiledCircuit;
  // Number of threads for the bb.js worker pool. Ignored in Node when
  // `backend` is set to Wasm. Defaults to 1 (single-threaded) when
  // omitted.
  threads?: number;
  // Force a specific bb.js backend. In browsers, leave undefined (bb.js
  // auto-picks WasmWorker). In Node tests, pass `BackendType.Wasm`.
  backend?: BackendType;
  // Optional existing bb.js runtime. Use this when proving multiple
  // circuits in one page so each circuit gets its own Noir/UltraHonk wrapper
  // without spawning another Barretenberg WASM instance.
  bb?: Barretenberg;
}

export class AttestationProver {
  private readonly init_opts: ProverInit;
  private noir: Noir | null = null;
  private api: Barretenberg | null = null;
  private backend: UltraHonkBackend | null = null;
  private ownsApi = false;

  constructor(init: ProverInit) {
    this.init_opts = init;
  }

  async init(): Promise<void> {
    if (this.noir && this.backend && this.api) return;
    this.noir = new Noir(this.init_opts.circuit);
    if (this.init_opts.bb) {
      this.api = this.init_opts.bb;
      this.ownsApi = false;
    } else {
      const opts: { threads?: number; backend?: BackendType } = {};
      if (this.init_opts.threads != null) opts.threads = this.init_opts.threads;
      if (this.init_opts.backend != null) opts.backend = this.init_opts.backend;
      // `Barretenberg.new` calls `initSRSChonk()` internally when an
      // explicit Wasm/WasmWorker backend is selected; calling it again
      // here traps the WASM with an "already initialized" unreachable.
      this.api = await Barretenberg.new(opts);
      this.ownsApi = true;
    }
    this.backend = new UltraHonkBackend(this.init_opts.circuit.bytecode, this.api);
  }

  async execute(
    inputs: AnyCircuitInputs,
  ): Promise<{ witness: Uint8Array; returnValue: unknown }> {
    if (!this.noir) await this.init();
    const { witness, returnValue } = await this.noir!.execute(
      inputs as unknown as InputMap,
    );
    return { witness, returnValue };
  }

  async prove(inputs: AnyCircuitInputs): Promise<ProofData> {
    if (!this.backend || !this.noir) await this.init();
    const { witness } = await this.noir!.execute(
      inputs as unknown as InputMap,
    );
    return this.backend!.generateProof(witness);
  }

  async verify(proof: ProofData): Promise<boolean> {
    if (!this.backend) await this.init();
    return this.backend!.verifyProof(proof);
  }

  async destroy(): Promise<void> {
    if (this.ownsApi) {
      await this.api?.destroy();
    }
    this.api = null;
    this.backend = null;
    this.noir = null;
    this.ownsApi = false;
  }
}
