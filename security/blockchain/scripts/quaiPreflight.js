/**
 * @file quaiPreflight.js
 * @description Preflight validation script for Quai Network Orchard Cyprus-1 testnet.
 *
 * Implements Stage 4.3 requirements:
 *   1. Network parameters: Quai Orchard Cyprus-1 (zone 0,0), chainId 9000, configurable RPC.
 *   2. Network connectivity check: JSON-RPC reachability (eth_chainId, eth_blockNumber).
 *   3. Chain ID verification: ensures remote chain matches expected zone chain ID.
 *   4. Account balance check: verifies account has funds for deployment/anchoring if key/address provided.
 *   5. Diagnostic report: outputs clear diagnostics.
 *   6. Graceful offline fallback: if testnet is unreachable or offline, reports cleanly without throwing/crashing.
 */

import { ethers } from 'ethers';

export const DEFAULT_QUAI_CYPRUS1_RPC = 'https://orchard.rpc.quai.network/cyprus1';
export const DEFAULT_QUAI_CYPRUS1_CHAIN_ID = 9000;
export const QUAI_ZONE_NAME = 'Cyprus-1 (zone-0-0)';

/**
 * Validate Quai Network connectivity, chain ID, and account balance.
 *
 * @param {object} [options={}]
 * @param {string} [options.rpcUrl] - RPC URL to probe.
 * @param {number} [options.expectedChainId] - Expected chain ID.
 * @param {string} [options.privateKey] - Optional submitter private key.
 * @param {string} [options.accountAddress] - Optional account address to check balance.
 * @param {number} [options.timeoutMs=5000] - Request timeout in milliseconds.
 * @param {object} [options.customFetch] - Optional custom fetch function for testing.
 * @returns {Promise<object>} Diagnostic result.
 */
export async function validateQuaiPreflight(options = {}) {
  const rpcUrl = options.rpcUrl || process.env.QUAI_RPC_URL || DEFAULT_QUAI_CYPRUS1_RPC;
  const expectedChainId = Number.parseInt(
    options.expectedChainId || process.env.QUAI_CHAIN_ID || DEFAULT_QUAI_CYPRUS1_CHAIN_ID,
    10
  );
  const privateKey = options.privateKey || process.env.QUAI_PRIVATE_KEY || null;
  const timeoutMs = options.timeoutMs ?? 5000;
  const fetchFn = options.customFetch || globalThis.fetch;

  let accountAddress = options.accountAddress || null;
  if (!accountAddress && privateKey) {
    try {
      const wallet = new ethers.Wallet(privateKey);
      accountAddress = wallet.address;
    } catch {
      // Invalid private key format
      accountAddress = 'INVALID_PRIVATE_KEY_FORMAT';
    }
  }

  const result = {
    network: 'Quai Orchard Testnet',
    zone: QUAI_ZONE_NAME,
    rpcUrl,
    expectedChainId,
    accountAddress,
    reachable: false,
    chainId: null,
    chainIdMatches: false,
    blockNumber: null,
    balanceWei: null,
    balanceEth: null,
    hasSufficientBalance: false,
    status: 'UNKNOWN',
    message: '',
    error: null,
  };

  // Helper for JSON-RPC POST with timeout
  async function rpcCall(method, params = []) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const resp = await fetchFn(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method,
          params,
        }),
        signal: controller.signal,
      });

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
      }

      const json = await resp.json();
      if (json.error) {
        throw new Error(`RPC error: ${json.error.message || JSON.stringify(json.error)}`);
      }
      return json.result;
    } finally {
      clearTimeout(timer);
    }
  }

  try {
    // 1. Connectivity and Chain ID check
    const chainIdHex = await rpcCall('eth_chainId');
    const remoteChainId = Number.parseInt(chainIdHex, 16);
    result.reachable = true;
    result.chainId = remoteChainId;
    result.chainIdMatches = remoteChainId === expectedChainId;

    // 2. Block number check
    const blockNumHex = await rpcCall('eth_blockNumber');
    result.blockNumber = Number.parseInt(blockNumHex, 16);

    // 3. Account balance check (if address provided)
    if (accountAddress && accountAddress !== 'INVALID_PRIVATE_KEY_FORMAT') {
      try {
        const balHex = await rpcCall('eth_getBalance', [accountAddress, 'latest']);
        const balBigInt = BigInt(balHex || '0x0');
        result.balanceWei = balBigInt.toString();
        result.balanceEth = ethers.formatEther(balBigInt);
        result.hasSufficientBalance = balBigInt > 0n;
      } catch (balErr) {
        result.error = `Failed to query balance: ${balErr.message}`;
      }
    }

    if (!result.chainIdMatches) {
      result.status = 'CHAIN_ID_MISMATCH';
      result.message = `Remote chain ID (${remoteChainId}) does not match expected (${expectedChainId}).`;
    } else if (accountAddress && !result.hasSufficientBalance) {
      result.status = 'LOW_BALANCE';
      result.message = `Submitter account ${accountAddress} has 0 QUAI balance.`;
    } else {
      result.status = 'READY';
      result.message = `Quai Network ${QUAI_ZONE_NAME} is reachable and responsive.`;
    }
  } catch (err) {
    // Graceful offline fallback
    result.reachable = false;
    result.status = 'OFFLINE_FALLBACK';
    result.error = err.message;
    result.message = `Quai testnet endpoint unreachable (${err.message}) — falling back cleanly to offline/mock mode.`;
  }

  return result;
}

/**
 * CLI execution entrypoint
 */
export async function runCli() {
  console.log('='.repeat(65));
  console.log('  HHH — Quai Network Orchard Cyprus-1 Preflight Check');
  console.log('='.repeat(65));

  const report = await validateQuaiPreflight();

  console.log(`Target Network : ${report.network} [${report.zone}]`);
  console.log(`RPC Endpoint   : ${report.rpcUrl}`);
  console.log(`Expected Chain : ${report.expectedChainId}`);
  console.log(`RPC Reachable  : ${report.reachable ? 'YES' : 'NO'}`);

  if (report.reachable) {
    console.log(`Reported Chain : ${report.chainId} (${report.chainIdMatches ? 'MATCH' : 'MISMATCH'})`);
    console.log(`Latest Block   : ${report.blockNumber}`);
    if (report.accountAddress) {
      console.log(`Submitter Acct : ${report.accountAddress}`);
      console.log(`Balance        : ${report.balanceEth ?? '0'} QUAI`);
    }
  } else {
    console.log(`Fallback Mode  : ACTIVE (Offline / Sandbox environment)`);
    console.log(`Diagnostic     : ${report.message}`);
  }

  console.log(`Preflight Status: [${report.status}]`);
  console.log('='.repeat(65));
  return report;
}

// Execute if run directly
if (process.argv[1] && process.argv[1].endsWith('quaiPreflight.js')) {
  runCli().then(() => process.exit(0)).catch((err) => {
    console.error('Preflight error:', err);
    process.exit(0); // Graceful exit even on error
  });
}
