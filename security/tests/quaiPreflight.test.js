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
  QUAI_ORCHARD_TESTNET_CHAIN_ID,
  QUAI_MAINNET_CHAIN_ID,
  QUAI_ZONE_NAME,
} from '../blockchain/scripts/quaiPreflight.js';

test('1. Preflight defaults match Quai Orchard Cyprus-1 specification', () => {
  assert.equal(DEFAULT_QUAI_CYPRUS1_RPC, 'https://orchard.rpc.quai.network/cyprus1');
  assert.equal(DEFAULT_QUAI_CYPRUS1_CHAIN_ID, 15000);
  assert.equal(QUAI_ORCHARD_TESTNET_CHAIN_ID, 15000);
  assert.equal(QUAI_MAINNET_CHAIN_ID, 9);
  assert.ok(QUAI_ZONE_NAME.includes('Cyprus-1'));
});

test('2. Successful preflight with mock online RPC provider returning 15000 (0x3a98)', async () => {
  const customFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === 'eth_chainId') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x3a98' }) }; // 15000 in hex
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
    rpcUrl: 'http://mock-quai-node:15000',
    expectedChainId: 15000,
    accountAddress: '0x0011223344556677889900112233445566778899',
    customFetch,
  });

  assert.equal(report.reachable, true);
  assert.equal(report.chainId, 15000);
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
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x1' }) }; // Ethereum Mainnet (1) instead of 15000
    }
    if (body.method === 'eth_blockNumber') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x50' }) };
    }
    throw new Error(`Unhandled method ${body.method}`);
  };

  const report = await validateQuaiPreflight({
    rpcUrl: 'http://mock-quai-node:15000',
    expectedChainId: 15000,
    customFetch,
  });

  assert.equal(report.reachable, true);
  assert.equal(report.chainId, 1);
  assert.equal(report.chainIdMatches, false);
  assert.equal(report.status, 'CHAIN_ID_MISMATCH');
  assert.ok(report.message.includes('does not match expected'));
});

test('4. Detects and flags Quai Mainnet (chain ID 9) when expecting Orchard Testnet (15000)', async () => {
  const customFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === 'eth_chainId') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x9' }) }; // Quai Mainnet (9)
    }
    if (body.method === 'eth_blockNumber') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x1000' }) };
    }
    throw new Error(`Unhandled method ${body.method}`);
  };

  const report = await validateQuaiPreflight({
    expectedChainId: 15000,
    customFetch,
  });

  assert.equal(report.reachable, true);
  assert.equal(report.chainId, 9);
  assert.equal(report.chainIdMatches, false);
  assert.equal(report.status, 'CHAIN_ID_MISMATCH');
  assert.ok(report.message.includes('Mainnet transactions are prohibited in testnet environment'));
});

test('5. Respects process.env.QUAI_CHAIN_ID override', async () => {
  const originalEnv = process.env.QUAI_CHAIN_ID;
  try {
    process.env.QUAI_CHAIN_ID = '15001';
    const customFetch = async (url, options) => {
      const body = JSON.parse(options.body);
      if (body.method === 'eth_chainId') {
        return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x3a99' }) }; // 15001
      }
      if (body.method === 'eth_blockNumber') {
        return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x10' }) };
      }
      throw new Error(`Unhandled method ${body.method}`);
    };

    const report = await validateQuaiPreflight({ customFetch });
    assert.equal(report.expectedChainId, 15001);
    assert.equal(report.chainId, 15001);
    assert.equal(report.chainIdMatches, true);
    assert.equal(report.status, 'READY');
  } finally {
    if (originalEnv === undefined) {
      delete process.env.QUAI_CHAIN_ID;
    } else {
      process.env.QUAI_CHAIN_ID = originalEnv;
    }
  }
});

test('6. Graceful offline fallback when testnet RPC is unreachable', async () => {
  const customFetch = async () => {
    throw new Error('connect ECONNREFUSED 127.0.0.1:15000');
  };

  const report = await validateQuaiPreflight({
    rpcUrl: 'http://unreachable-host:15000',
    expectedChainId: 15000,
    customFetch,
  });

  assert.equal(report.reachable, false);
  assert.equal(report.status, 'OFFLINE_FALLBACK');
  assert.ok(report.message.includes('falling back cleanly'));
  assert.ok(report.error.includes('ECONNREFUSED'));
});

test('7. Detects low balance for configured submitter account', async () => {
  const customFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === 'eth_chainId') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x3a98' }) };
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
    expectedChainId: 15000,
    accountAddress: '0x0011223344556677889900112233445566778899',
    customFetch,
  });

  assert.equal(report.reachable, true);
  assert.equal(report.hasSufficientBalance, false);
  assert.equal(report.status, 'LOW_BALANCE');
  assert.ok(report.message.includes('0 QUAI balance'));
});
