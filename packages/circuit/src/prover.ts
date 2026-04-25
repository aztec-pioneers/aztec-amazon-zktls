// Stateful wrapper around noir_js + bb.js. Keeps the Noir executor and the
// UltraHonk backend alive across proofs so callers don't pay init cost per
// call. bb.js 3.x split the backend into a long-lived `Barretenberg` API
// instance plus a thin `UltraHonkBackend` wrapper that takes bytecode + api.

import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import {
  Barretenberg,
  BackendType,
  UltraHonkBackend,
  type ProofData,
} from "@aztec/bb.js";
import type { CircuitInputs } from "./types.js";

export interface ProverInit {
  circuit: CompiledCircuit;
}

export class AttestationProver {
  private readonly circuit: CompiledCircuit;
  private noir: Noir | null = null;
  private api: Barretenberg | null = null;
  private backend: UltraHonkBackend | null = null;

  constructor(init: ProverInit) {
    this.circuit = init.circuit;
  }

  async init(): Promise<void> {
    if (this.noir && this.backend && this.api) return;
    this.noir = new Noir(this.circuit);
    // Force the WASM backend: Barretenberg.new() defaults to NativeUnixSocket
    // in Node, which spins up a `bb` subprocess and a UDS — we don't want
    // that side-channel for a vitest run.
    // `Barretenberg.new` already calls `initSRSChonk()` internally when an
    // explicit Wasm backend is requested; calling it again here traps the
    // WASM with an "already initialized" unreachable.
    this.api = await Barretenberg.new({ backend: BackendType.Wasm });
    this.backend = new UltraHonkBackend(this.circuit.bytecode, this.api);
  }

  async execute(
    inputs: CircuitInputs,
  ): Promise<{ witness: Uint8Array; returnValue: unknown }> {
    if (!this.noir) await this.init();
    const { witness, returnValue } = await this.noir!.execute(
      inputs as unknown as InputMap,
    );
    return { witness, returnValue };
  }

  async prove(inputs: CircuitInputs): Promise<ProofData> {
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
    await this.api?.destroy();
    this.api = null;
    this.backend = null;
    this.noir = null;
  }
}
