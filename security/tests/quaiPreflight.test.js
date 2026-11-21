/**
 * @file quaiPreflight.test.js
 * @description Unit tests for Quai Network Orchard Cyprus-1 preflight script.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateQuaiPreflight,
  DEFAULT_QUAI_CYPRUS1_RPC,
  DEFAULT_QUAI_CYPRUS1_CHAIN_ID,
  QUAI_ZONE_NAME,
} from '../blockchain/scripts/quaiPreflight.js';

test('1. Preflight defaults match Quai Orchard Cyprus-1 specification', () => {
  assert.equal(DEFAULT_QUAI_CYPRUS1_RPC, 'https://orchard.rpc.quai.network/cyprus1');
  assert.equal(DEFAULT_QUAI_CYPRUS1_CHAIN_ID, 9000);
  assert.ok(QUAI_ZONE_NAME.includes('Cyprus-1'));
});

test('2. Successful preflight with mock online RPC provider', async () => {
  const customFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === 'eth_chainId') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x2328' }) }; // 9000 in hex
    }
    if (body.method === 'eth_blockNumber') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x100' }) }; // 256
    }
    if (body.method === 'eth_getBalance') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0xde0b6b3a7640000' }) }; // 1 ETH in wei
    }
    throw new Error(`Unhandled method ${body.method}`);
  };

  const report = await validateQuaiPreflight({
    rpcUrl: 'http://mock-quai-node:9000',
    expectedChainId: 9000,
    accountAddress: '0x0011223344556677889900112233445566778899',
    customFetch,
  });

  assert.equal(report.reachable, true);
  assert.equal(report.chainId, 9000);
  assert.equal(report.chainIdMatches, true);
  assert.equal(report.blockNumber, 256);
  assert.equal(report.hasSufficientBalance, true);
  assert.equal(report.status, 'READY');
  assert.ok(report.message.includes('reachable and responsive'));
});

test('3. Detects chain ID mismatch when connecting to wrong zone or network', async () => {
  const customFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === 'eth_chainId') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x1' }) }; // Mainnet (1) instead of 9000
    }
    if (body.method === 'eth_blockNumber') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x50' }) };
    }
    throw new Error(`Unhandled method ${body.method}`);
  };

  const report = await validateQuaiPreflight({
    rpcUrl: 'http://mock-quai-node:9000',
    expectedChainId: 9000,
    customFetch,
  });

  assert.equal(report.reachable, true);
  assert.equal(report.chainId, 1);
  assert.equal(report.chainIdMatches, false);
  assert.equal(report.status, 'CHAIN_ID_MISMATCH');
  assert.ok(report.message.includes('does not match expected'));
});

test('4. Graceful offline fallback when testnet RPC is unreachable', async () => {
  const customFetch = async () => {
    throw new Error('connect ECONNREFUSED 127.0.0.1:9000');
  };

  const report = await validateQuaiPreflight({
    rpcUrl: 'http://unreachable-host:9000',
    expectedChainId: 9000,
    customFetch,
  });

  assert.equal(report.reachable, false);
  assert.equal(report.status, 'OFFLINE_FALLBACK');
  assert.ok(report.message.includes('falling back cleanly'));
  assert.ok(report.error.includes('ECONNREFUSED'));
});

test('5. Detects low balance for configured submitter account', async () => {
  const customFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === 'eth_chainId') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x2328' }) };
    }
    if (body.method === 'eth_blockNumber') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x100' }) };
    }
    if (body.method === 'eth_getBalance') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x0' }) }; // 0 balance
    }
    throw new Error(`Unhandled method ${body.method}`);
  };

  const report = await validateQuaiPreflight({
    expectedChainId: 9000,
    accountAddress: '0x0011223344556677889900112233445566778899',
    customFetch,
  });

  assert.equal(report.reachable, true);
  assert.equal(report.hasSufficientBalance, false);
  assert.equal(report.status, 'LOW_BALANCE');
  assert.ok(report.message.includes('0 QUAI balance'));
});
