import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeText, runDFA } from '../src/engine/analyzer.js';

test('safe marketplace text stays in q0', () => {
  const analysis = analyzeText('Produk original, pembayaran melalui aplikasi marketplace, bisa checkout langsung.');
  assert.equal(analysis.result.state, 'q0');
  assert.equal(analysis.result.label, 'Safe');
});

test('one suspicious indicator reaches q1', () => {
  const analysis = analyzeText('Bisa hubungi WhatsApp saya untuk tanya stok.');
  assert.equal(analysis.result.state, 'q1');
  assert.equal(analysis.result.label, 'Low Risk');
});

test('two suspicious indicators reach q2', () => {
  const analysis = analyzeText('Stok tinggal satu, hubungi WhatsApp saya.');
  assert.equal(analysis.result.state, 'q2');
  assert.equal(analysis.result.label, 'Medium Risk');
});

test('three or more suspicious indicators reach q3 accepting state', () => {
  const analysis = analyzeText('Harga murah banget, stok tinggal satu, bayar langsung saja biar cepat.');
  assert.equal(analysis.result.state, 'q3');
  assert.equal(analysis.result.isScamAlert, true);
});

test('dfa transition is deterministic', () => {
  const dfa = runDFA(['C', 'U', 'P', 'O']);
  assert.deepEqual(dfa.trace.map((step) => step.to), ['q1', 'q2', 'q3', 'q3']);
  assert.equal(dfa.finalState, 'q3');
});
