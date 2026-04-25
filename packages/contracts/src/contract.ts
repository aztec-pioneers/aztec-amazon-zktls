import { AztecAddress } from "@aztec/aztec.js/addresses";
import type { FieldLike } from "@aztec/aztec.js/abi";
import type {
  ContractInstanceWithAddress,
  InteractionWaitOptions,
  SendInteractionOptions,
  SimulateInteractionOptions,
} from "@aztec/aztec.js/contracts";
import { Fr } from "@aztec/aztec.js/fields";
import type { AztecNode } from "@aztec/aztec.js/node";
import { TxHash } from "@aztec/aztec.js/tx";
import type { Wallet } from "@aztec/aztec.js/wallet";
import { AuthWitness } from "@aztec/stdlib/auth-witness";
import { deriveKeys } from "@aztec/stdlib/keys";
import {
  AmazonEscrowContract,
  AmazonEscrowContractArtifact,
} from "./artifacts/escrow/AmazonEscrow.js";
import {
  AttestorKeyOracleContract,
  AttestorKeyOracleContractArtifact,
} from "./artifacts/oracle/AttestorKeyOracle.js";
import {
  TokenContract,
  TokenContractArtifact,
} from "./artifacts/token/Token.js";
import { type EscrowConfig } from "./constants.js";

/**
 * Deploys a fresh AmazonEscrow contract. One escrow per order, OTC-style.
 *
 * Uses the "pubkey pattern": the contract is deployed with its own random
 * secret key. Every wallet that needs to read notes from this escrow must
 * later call `wallet.registerContract(instance, artifact, secretKey)`.
 */
export async function deployEscrowContract(
  wallet: Wallet,
  from: AztecAddress,
  paymentToken: AztecAddress,
  amount: bigint,
  asin: FieldLike,
  addressCommitment: FieldLike,
  oracleAddress: AztecAddress,
  opts: { send: SendInteractionOptions<InteractionWaitOptions> } = {
    send: { from },
  },
): Promise<{
  contract: AmazonEscrowContract;
  instance: ContractInstanceWithAddress;
  secretKey: Fr;
}> {
  const secretKey = Fr.random();
  const contractPublicKeys = (await deriveKeys(secretKey)).publicKeys;

  const contractDeployment = await AmazonEscrowContract.deployWithPublicKeys(
    contractPublicKeys,
    wallet,
    paymentToken,
    amount,
    asin,
    addressCommitment,
    oracleAddress,
  );
  const instance = await contractDeployment.getInstance();

  await wallet.registerContract(instance, AmazonEscrowContractArtifact, secretKey);

  const sendOpts: SendInteractionOptions<InteractionWaitOptions> = {
    additionalScopes: [instance.address],
    ...opts.send,
  };
  const { contract } = await contractDeployment.send(sendOpts);
  return { contract, instance, secretKey };
}

/**
 * Deploys the AttestorKeyOracle. `admin` is the only address that can later
 * call `add_key`. The oracle stores allowed pubkey hashes in a public
 * immutable map (one slot per hash, write-once).
 */
export async function deployOracleContract(
  wallet: Wallet,
  from: AztecAddress,
  admin: AztecAddress,
  opts: { send: SendInteractionOptions<InteractionWaitOptions> } = {
    send: { from },
  },
): Promise<{
  contract: AttestorKeyOracleContract;
  instance: ContractInstanceWithAddress;
}> {
  const contractDeployment = await AttestorKeyOracleContract.deploy(wallet, admin);
  const instance = await contractDeployment.getInstance();
  const { contract } = await contractDeployment.send(opts.send);
  return { contract, instance };
}

/**
 * Admin call: register an attestor's pubkey hash as allowed. Once set, the
 * slot is permanent (PublicImmutable).
 */
export async function addOracleKey(
  wallet: Wallet,
  from: AztecAddress,
  oracle: AttestorKeyOracleContract,
  pubkeyHash: FieldLike,
  opts: { send: SendInteractionOptions<InteractionWaitOptions> } = {
    send: { from },
  },
): Promise<TxHash> {
  const { receipt } = await oracle
    .withWallet(wallet)
    .methods.add_key(pubkeyHash)
    .send(opts.send);
  return receipt.txHash;
}

/**
 * Deploys an aztec-standards Token. `from` becomes the minter.
 */
export async function deployTokenContract(
  wallet: Wallet,
  from: AztecAddress,
  tokenMetadata: { name: string; symbol: string; decimals: number },
  opts: { send: SendInteractionOptions<InteractionWaitOptions> } = {
    send: { from },
  },
): Promise<{
  contract: TokenContract;
  instance: ContractInstanceWithAddress;
}> {
  const contractDeployment = await TokenContract.deployWithOpts(
    { wallet, method: "constructor_with_minter" },
    tokenMetadata.name,
    tokenMetadata.symbol,
    tokenMetadata.decimals,
    from,
  );
  const instance = await contractDeployment.getInstance();
  const { contract } = await contractDeployment.send(opts.send);
  return { contract, instance };
}

/**
 * Order creator deposits the bounty into the escrow. Authwit grants the
 * escrow permission to call `transfer_private_to_private(from, escrow, ...)`
 * on the payment token.
 */
export async function depositToEscrow(
  wallet: Wallet,
  from: AztecAddress,
  escrow: AmazonEscrowContract,
  token: TokenContract,
  amount: bigint,
  opts: { send: SendInteractionOptions<InteractionWaitOptions> } = {
    send: { from, additionalScopes: [escrow.address] },
  },
): Promise<TxHash> {
  const escrowWithWallet = escrow.withWallet(wallet);
  const { nonce, authwit } = await getPrivateTransferAuthwit(
    wallet,
    from,
    token,
    escrow.address,
    escrow.address,
    amount,
  );
  const { receipt } = await escrowWithWallet.methods
    .deposit_tokens(nonce)
    .with({ authWitnesses: [authwit] })
    .send(opts.send);
  return receipt.txHash;
}

/**
 * Inputs to the escrow's `fill_order` private function. Mirrors the Noir
 * verify(...) argset 1:1 - same shape the circuit takes.
 *
 * BoundedVec args are passed as `{ storage, len }` from
 * @amazon-zktls/circuit's parseAttestationToInputs; we forward the raw
 * storage array since aztec.js encodes BoundedVec<u8, N> as a flat byte
 * array.
 */
export type FillOrderArgs = {
  publicKeyX: number[]; // 32
  publicKeyY: number[]; // 32
  hash: number[]; // 32
  signature: number[]; // 64
  allowedUrl: { storage: number[]; len: number };
  requestUrl: { storage: number[]; len: number };
  recipient: number[]; // 20
  timestamp: bigint | number;
  hashes: {
    shipment_status: number[]; // 32
    product_title: number[]; // 32
    ship_to: number[]; // 32
    grand_total: number[]; // 32
  };
  contents: {
    shipment_status: { storage: number[]; len: number };
    product_title: { storage: number[]; len: number };
    ship_to: { storage: number[]; len: number };
    grand_total: { storage: number[]; len: number };
  };
  shipToHints: {
    offsets: number[]; // 4
    lens: number[]; // 4
  };
  grandTotalLen: number;
};

/**
 * Filler claims the bounty by submitting a Primus zkTLS attestation. The
 * Noir contract re-runs `amazon_zktls_lib::verify(...)` inline and asserts
 * outputs.{asin,address_commitment} match the order config. The contract
 * pays itself out, so no authwit is needed on the caller side.
 */
export async function fillOrder(
  wallet: Wallet,
  from: AztecAddress,
  escrow: AmazonEscrowContract,
  args: FillOrderArgs,
  opts: { send: SendInteractionOptions<InteractionWaitOptions> } = {
    send: { from, additionalScopes: [escrow.address] },
  },
): Promise<TxHash> {
  const escrowWithWallet = escrow.withWallet(wallet);
  // For BoundedVec<u8, N> args, aztec.js takes a JS array of actual length
  // and pads to N internally; passing the pre-padded storage would set
  // BoundedVec.len = N which breaks length-aware logic (URL prefix check,
  // sha256_var, etc). Slice to the real `len`.
  const slice = (bv: { storage: number[]; len: number }) =>
    bv.storage.slice(0, bv.len);
  const { receipt } = await escrowWithWallet.methods
    .fill_order(
      args.publicKeyX,
      args.publicKeyY,
      args.hash,
      args.signature,
      slice(args.allowedUrl),
      slice(args.requestUrl),
      args.recipient,
      args.timestamp,
      args.hashes,
      {
        shipment_status: slice(args.contents.shipment_status),
        product_title: slice(args.contents.product_title),
        ship_to: slice(args.contents.ship_to),
        grand_total: slice(args.contents.grand_total),
      },
      args.shipToHints,
      args.grandTotalLen,
    )
    .send(opts.send);
  return receipt.txHash;
}

/**
 * Build an authwit allowing `caller` to invoke
 * `token.transfer_private_to_private(from, to, amount, nonce)`.
 * Returns the authwit + the random nonce that must be passed into the same
 * interaction.
 */
export async function getPrivateTransferAuthwit(
  wallet: Wallet,
  from: AztecAddress,
  token: TokenContract,
  caller: AztecAddress,
  to: AztecAddress,
  amount: bigint,
): Promise<{ authwit: AuthWitness; nonce: Fr }> {
  const nonce = Fr.random();
  const call = await token
    .withWallet(wallet)
    .methods.transfer_private_to_private(from, to, amount, nonce)
    .getFunctionCall();
  const authwit = await wallet.createAuthWit(from, { caller, call });
  return { authwit, nonce };
}

export async function getEscrowConfig(
  wallet: Wallet,
  escrow: AmazonEscrowContract,
): Promise<EscrowConfig> {
  const { result } = await escrow
    .withWallet(wallet)
    .methods.get_config()
    .simulate({ from: escrow.address });
  return result as EscrowConfig;
}

export async function expectBalancePrivate(
  wallet: Wallet,
  from: AztecAddress,
  token: TokenContract,
  expectedBalance: bigint,
  opts: SimulateInteractionOptions = { from },
): Promise<boolean> {
  const { result: empiricalBalance } = await token
    .withWallet(wallet)
    .methods.balance_of_private(from)
    .simulate(opts);
  return empiricalBalance === expectedBalance;
}

export async function balanceOfPrivate(
  wallet: Wallet,
  from: AztecAddress,
  token: TokenContract,
  opts: SimulateInteractionOptions = { from },
): Promise<bigint> {
  const { result } = await token
    .withWallet(wallet)
    .methods.balance_of_private(from)
    .simulate(opts);
  return result as bigint;
}

export async function getTokenContract(
  wallet: Wallet,
  node: AztecNode,
  tokenAddress: AztecAddress,
): Promise<TokenContract> {
  const contractInstance = await node.getContract(tokenAddress);
  if (!contractInstance) {
    throw new Error(`No instance for token contract at ${tokenAddress.toString()} found!`);
  }
  await wallet.registerContract(contractInstance, TokenContractArtifact);
  return TokenContract.at(tokenAddress, wallet);
}

/**
 * Register an existing escrow on a SECOND wallet so it can read notes from
 * the escrow (the "pubkey pattern"). Required for any wallet other than the
 * deployer's that needs to interact with this escrow.
 */
export async function getEscrowContract(
  wallet: Wallet,
  escrowAddress: AztecAddress,
  contractInstance: ContractInstanceWithAddress,
  escrowSecretKey: Fr,
): Promise<AmazonEscrowContract> {
  await wallet.registerContract(
    contractInstance,
    AmazonEscrowContractArtifact,
    escrowSecretKey,
  );
  await wallet.registerSender(escrowAddress);
  return AmazonEscrowContract.at(escrowAddress, wallet);
}

export async function getOracleContract(
  wallet: Wallet,
  node: AztecNode,
  oracleAddress: AztecAddress,
): Promise<AttestorKeyOracleContract> {
  const contractInstance = await node.getContract(oracleAddress);
  if (!contractInstance) {
    throw new Error(`No instance for oracle at ${oracleAddress.toString()}`);
  }
  await wallet.registerContract(contractInstance, AttestorKeyOracleContractArtifact);
  return AttestorKeyOracleContract.at(oracleAddress, wallet);
}
