/**
 * S-AES (Simplified Advanced Encryption Standard) Core Implementation
 * 
 * Parameters:
 * - Block size: 16 bits (2×2 nibble state matrix)
 * - Key size: 16 bits
 * - Rounds: 2 (+1 initial AddRoundKey)
 * - Field: GF(2^4) with irreducible polynomial x^4 + x + 1 (0x13)
 * 
 * Reference: Schaefer, E. F., & Waidner, M. (1998).
 *            A Simplified AES Algorithm and Its Linear and Differential Cryptanalysis.
 */

// =====================================================
// CONSTANTS
// =====================================================

const SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
              0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7];

const INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF,
                  0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE];

const RCON1 = 0x80; // 10000000
const RCON2 = 0x30; // 00110000

const MIX_MATRIX     = [[1, 4], [4, 1]];
const INV_MIX_MATRIX = [[9, 2], [2, 9]];

// =====================================================
// UTILITY / FORMAT FUNCTIONS
// =====================================================

function nibbleToBin(n) {
    return (n & 0xF).toString(2).padStart(4, '0');
}

function nibbleToHex(n) {
    return (n & 0xF).toString(16).toUpperCase();
}

function byteToBin(b) {
    return (b & 0xFF).toString(2).padStart(8, '0');
}

function byteToHex(b) {
    return (b & 0xFF).toString(16).toUpperCase().padStart(2, '0');
}

function word16ToBin(w) {
    return (w & 0xFFFF).toString(2).padStart(16, '0');
}

function word16ToHex(w) {
    return (w & 0xFFFF).toString(16).toUpperCase().padStart(4, '0');
}

/**
 * Convert a 16-bit binary string to a 2×2 state matrix.
 * State is filled COLUMN by COLUMN:
 *   | state[0][0]  state[0][1] |
 *   | state[1][0]  state[1][1] |
 *
 * bits[0:3]   → state[0][0]  (row 0, col 0)
 * bits[4:7]   → state[1][0]  (row 1, col 0)
 * bits[8:11]  → state[0][1]  (row 0, col 1)
 * bits[12:15] → state[1][1]  (row 1, col 1)
 */
function binaryToState(binStr) {
    const n0 = parseInt(binStr.substring(0, 4), 2);
    const n1 = parseInt(binStr.substring(4, 8), 2);
    const n2 = parseInt(binStr.substring(8, 12), 2);
    const n3 = parseInt(binStr.substring(12, 16), 2);
    return [[n0, n2], [n1, n3]];
}

/** Convert state matrix back to 16-bit binary string (column-major). */
function stateToBinary(state) {
    return nibbleToBin(state[0][0]) + nibbleToBin(state[1][0]) +
           nibbleToBin(state[0][1]) + nibbleToBin(state[1][1]);
}

/** Convert state matrix to hex string. */
function stateToHex(state) {
    return nibbleToHex(state[0][0]) + nibbleToHex(state[1][0]) +
           nibbleToHex(state[0][1]) + nibbleToHex(state[1][1]);
}

/** Deep clone a 2×2 state matrix. */
function cloneState(state) {
    return [[state[0][0], state[0][1]], [state[1][0], state[1][1]]];
}

// =====================================================
// GF(2^4) ARITHMETIC
// =====================================================

/**
 * Addition in GF(2^4) — simply XOR.
 */
function gfAdd(a, b) {
    return (a ^ b) & 0xF;
}

/**
 * Multiplication in GF(2^4) with irreducible polynomial x^4 + x + 1 (0x13).
 * Uses the shift-and-XOR method.
 */
function gfMul(a, b) {
    let result = 0;
    let tempA = a & 0xF;
    let tempB = b & 0xF;

    for (let i = 0; i < 4; i++) {
        if (tempB & 1) {
            result ^= tempA;
        }
        tempB >>= 1;
        tempA <<= 1;
        if (tempA & 0x10) {          // overflow into bit-4
            tempA ^= 0x13;           // reduce mod x^4 + x + 1
        }
    }
    return result & 0xF;
}

// =====================================================
// S-BOX OPERATIONS
// =====================================================

function subNibble(nibble)    { return SBOX[nibble & 0xF]; }
function invSubNibble(nibble) { return INV_SBOX[nibble & 0xF]; }

// =====================================================
// KEY EXPANSION
// =====================================================

/**
 * RotWord: swap the two nibbles in an 8-bit word.
 * N0||N1 → N1||N0
 */
function rotWord(word8) {
    const high = (word8 >> 4) & 0xF;
    const low  = word8 & 0xF;
    return (low << 4) | high;
}

/**
 * SubWord: apply S-Box to each nibble of an 8-bit word.
 */
function subWord(word8) {
    const high = (word8 >> 4) & 0xF;
    const low  = word8 & 0xF;
    return (SBOX[high] << 4) | SBOX[low];
}

/**
 * Key Expansion: generate K0, K1, K2 from a 16-bit key.
 * Returns { w: [w0..w5], keys: [K0, K1, K2], log }.
 */
function keyExpansion(key16) {
    const log = { steps: [] };

    const w0 = (key16 >> 8) & 0xFF;
    const w1 = key16 & 0xFF;

    log.steps.push({ desc: 'w0 = upper 8 bits of key', value: w0, binary: byteToBin(w0), hex: byteToHex(w0) });
    log.steps.push({ desc: 'w1 = lower 8 bits of key', value: w1, binary: byteToBin(w1), hex: byteToHex(w1) });

    // --- w2 ---
    const rotW1 = rotWord(w1);
    log.steps.push({ desc: 'RotWord(w1)', input: byteToBin(w1), output: byteToBin(rotW1), hexIn: byteToHex(w1), hexOut: byteToHex(rotW1) });

    const subRotW1 = subWord(rotW1);
    log.steps.push({ desc: 'SubWord(RotWord(w1))', input: byteToBin(rotW1), output: byteToBin(subRotW1), hexIn: byteToHex(rotW1), hexOut: byteToHex(subRotW1) });

    const w2 = (w0 ^ subRotW1 ^ RCON1) & 0xFF;
    log.steps.push({
        desc: 'w2 = w0 ⊕ SubWord(RotWord(w1)) ⊕ RCON1',
        calculation: `${byteToBin(w0)} ⊕ ${byteToBin(subRotW1)} ⊕ ${byteToBin(RCON1)}`,
        value: w2, binary: byteToBin(w2), hex: byteToHex(w2)
    });

    // --- w3 ---
    const w3 = (w2 ^ w1) & 0xFF;
    log.steps.push({
        desc: 'w3 = w2 ⊕ w1',
        calculation: `${byteToBin(w2)} ⊕ ${byteToBin(w1)}`,
        value: w3, binary: byteToBin(w3), hex: byteToHex(w3)
    });

    // --- w4 ---
    const rotW3 = rotWord(w3);
    log.steps.push({ desc: 'RotWord(w3)', input: byteToBin(w3), output: byteToBin(rotW3), hexIn: byteToHex(w3), hexOut: byteToHex(rotW3) });

    const subRotW3 = subWord(rotW3);
    log.steps.push({ desc: 'SubWord(RotWord(w3))', input: byteToBin(rotW3), output: byteToBin(subRotW3), hexIn: byteToHex(rotW3), hexOut: byteToHex(subRotW3) });

    const w4 = (w2 ^ subRotW3 ^ RCON2) & 0xFF;
    log.steps.push({
        desc: 'w4 = w2 ⊕ SubWord(RotWord(w3)) ⊕ RCON2',
        calculation: `${byteToBin(w2)} ⊕ ${byteToBin(subRotW3)} ⊕ ${byteToBin(RCON2)}`,
        value: w4, binary: byteToBin(w4), hex: byteToHex(w4)
    });

    // --- w5 ---
    const w5 = (w4 ^ w3) & 0xFF;
    log.steps.push({
        desc: 'w5 = w4 ⊕ w3',
        calculation: `${byteToBin(w4)} ⊕ ${byteToBin(w3)}`,
        value: w5, binary: byteToBin(w5), hex: byteToHex(w5)
    });

    const K0 = (w0 << 8) | w1;
    const K1 = (w2 << 8) | w3;
    const K2 = (w4 << 8) | w5;

    log.w    = [w0, w1, w2, w3, w4, w5];
    log.keys = [K0, K1, K2];

    return { w: [w0, w1, w2, w3, w4, w5], keys: [K0, K1, K2], log };
}

// =====================================================
// STATE TRANSFORMATIONS — ENCRYPTION
// =====================================================

/** SubNibbles: substitute each nibble via S-Box. */
function applySubNibbles(state) {
    return [
        [subNibble(state[0][0]), subNibble(state[0][1])],
        [subNibble(state[1][0]), subNibble(state[1][1])]
    ];
}

/** ShiftRows: swap the two elements in row 1 (second row). */
function applyShiftRows(state) {
    return [
        [state[0][0], state[0][1]],
        [state[1][1], state[1][0]]
    ];
}

/**
 * MixColumns: multiply each column by [[1,4],[4,1]] in GF(2^4).
 * Returns { state, details } where details has per-column GF calculations.
 */
function applyMixColumns(state) {
    const details = [];
    const result = [[0, 0], [0, 0]];

    for (let col = 0; col < 2; col++) {
        const s0 = state[0][col];
        const s1 = state[1][col];

        const m1s0 = gfMul(MIX_MATRIX[0][0], s0);   // 1 × s0
        const m4s1 = gfMul(MIX_MATRIX[0][1], s1);   // 4 × s1
        const m4s0 = gfMul(MIX_MATRIX[1][0], s0);   // 4 × s0
        const m1s1 = gfMul(MIX_MATRIX[1][1], s1);   // 1 × s1

        result[0][col] = gfAdd(m1s0, m4s1);
        result[1][col] = gfAdd(m4s0, m1s1);

        details.push({
            column: col,
            input: [s0, s1],
            output: [result[0][col], result[1][col]],
            calculations: [
                {
                    label: `s'[0][${col}]`,
                    desc: `(${MIX_MATRIX[0][0]} × ${nibbleToHex(s0)}) ⊕ (${MIX_MATRIX[0][1]} × ${nibbleToHex(s1)})`,
                    terms: [
                        { a: MIX_MATRIX[0][0], b: s0, result: m1s0 },
                        { a: MIX_MATRIX[0][1], b: s1, result: m4s1 }
                    ],
                    xorResult: result[0][col]
                },
                {
                    label: `s'[1][${col}]`,
                    desc: `(${MIX_MATRIX[1][0]} × ${nibbleToHex(s0)}) ⊕ (${MIX_MATRIX[1][1]} × ${nibbleToHex(s1)})`,
                    terms: [
                        { a: MIX_MATRIX[1][0], b: s0, result: m4s0 },
                        { a: MIX_MATRIX[1][1], b: s1, result: m1s1 }
                    ],
                    xorResult: result[1][col]
                }
            ]
        });
    }

    return { state: result, details };
}

/** AddRoundKey: XOR state with the key (interpreted as state matrix). */
function applyAddRoundKey(state, key16) {
    const keyState = binaryToState(word16ToBin(key16));
    return [
        [state[0][0] ^ keyState[0][0], state[0][1] ^ keyState[0][1]],
        [state[1][0] ^ keyState[1][0], state[1][1] ^ keyState[1][1]]
    ];
}

// =====================================================
// STATE TRANSFORMATIONS — DECRYPTION (Inverse)
// =====================================================

/** InvSubNibbles: substitute via Inverse S-Box. */
function applyInvSubNibbles(state) {
    return [
        [invSubNibble(state[0][0]), invSubNibble(state[0][1])],
        [invSubNibble(state[1][0]), invSubNibble(state[1][1])]
    ];
}

/**
 * InvShiftRows: for a 2×2 matrix, shifting right by 1 is the same as
 * shifting left by 1 — both are a swap of row-1 elements.
 */
function applyInvShiftRows(state) {
    return applyShiftRows(state);
}

/**
 * InvMixColumns: multiply each column by [[9,2],[2,9]] in GF(2^4).
 * Returns { state, details }.
 */
function applyInvMixColumns(state) {
    const details = [];
    const result = [[0, 0], [0, 0]];

    for (let col = 0; col < 2; col++) {
        const s0 = state[0][col];
        const s1 = state[1][col];

        const m9s0 = gfMul(INV_MIX_MATRIX[0][0], s0);  // 9 × s0
        const m2s1 = gfMul(INV_MIX_MATRIX[0][1], s1);  // 2 × s1
        const m2s0 = gfMul(INV_MIX_MATRIX[1][0], s0);  // 2 × s0
        const m9s1 = gfMul(INV_MIX_MATRIX[1][1], s1);  // 9 × s1

        result[0][col] = gfAdd(m9s0, m2s1);
        result[1][col] = gfAdd(m2s0, m9s1);

        details.push({
            column: col,
            input: [s0, s1],
            output: [result[0][col], result[1][col]],
            calculations: [
                {
                    label: `s'[0][${col}]`,
                    desc: `(${INV_MIX_MATRIX[0][0]} × ${nibbleToHex(s0)}) ⊕ (${INV_MIX_MATRIX[0][1]} × ${nibbleToHex(s1)})`,
                    terms: [
                        { a: INV_MIX_MATRIX[0][0], b: s0, result: m9s0 },
                        { a: INV_MIX_MATRIX[0][1], b: s1, result: m2s1 }
                    ],
                    xorResult: result[0][col]
                },
                {
                    label: `s'[1][${col}]`,
                    desc: `(${INV_MIX_MATRIX[1][0]} × ${nibbleToHex(s0)}) ⊕ (${INV_MIX_MATRIX[1][1]} × ${nibbleToHex(s1)})`,
                    terms: [
                        { a: INV_MIX_MATRIX[1][0], b: s0, result: m2s0 },
                        { a: INV_MIX_MATRIX[1][1], b: s1, result: m9s1 }
                    ],
                    xorResult: result[1][col]
                }
            ]
        });
    }

    return { state: result, details };
}

// =====================================================
// MAIN FUNCTIONS: ENCRYPT & DECRYPT
// =====================================================

/**
 * Encrypt a 16-bit plaintext with a 16-bit key using S-AES.
 * Returns a detailed log of every step for the UI.
 */
function saesEncrypt(plaintextBin, keyBin) {
    const key16 = parseInt(keyBin, 2);

    const log = {
        mode: 'encrypt',
        input: { plaintext: plaintextBin, key: keyBin },
        keyExpansion: null,
        steps: [],
        result: null
    };

    // ---- Key Expansion ----
    const ke = keyExpansion(key16);
    log.keyExpansion = ke.log;
    const [K0, K1, K2] = ke.keys;

    // ---- Convert plaintext to state ----
    let state = binaryToState(plaintextBin);

    // ---- Initial AddRoundKey (K0) ----
    let before = cloneState(state);
    state = applyAddRoundKey(state, K0);
    log.steps.push({
        name: 'Initial AddRoundKey',
        operation: 'AddRoundKey (K0)',
        stateBefore: before,
        stateAfter: cloneState(state),
        key: K0,
        keyState: binaryToState(word16ToBin(K0))
    });

    // ---- Round 1 ----
    // SubNibbles
    before = cloneState(state);
    state = applySubNibbles(state);
    log.steps.push({
        name: 'Round 1 — SubNibbles',
        operation: 'SubNibbles',
        round: 1,
        stateBefore: before,
        stateAfter: cloneState(state)
    });

    // ShiftRows
    before = cloneState(state);
    state = applyShiftRows(state);
    log.steps.push({
        name: 'Round 1 — ShiftRows',
        operation: 'ShiftRows',
        round: 1,
        stateBefore: before,
        stateAfter: cloneState(state)
    });

    // MixColumns
    before = cloneState(state);
    const mc = applyMixColumns(state);
    state = mc.state;
    log.steps.push({
        name: 'Round 1 — MixColumns',
        operation: 'MixColumns',
        round: 1,
        stateBefore: before,
        stateAfter: cloneState(state),
        gfDetails: mc.details
    });

    // AddRoundKey K1
    before = cloneState(state);
    state = applyAddRoundKey(state, K1);
    log.steps.push({
        name: 'Round 1 — AddRoundKey',
        operation: 'AddRoundKey (K1)',
        round: 1,
        stateBefore: before,
        stateAfter: cloneState(state),
        key: K1,
        keyState: binaryToState(word16ToBin(K1))
    });

    // ---- Round 2 (Final — no MixColumns) ----
    // SubNibbles
    before = cloneState(state);
    state = applySubNibbles(state);
    log.steps.push({
        name: 'Round 2 — SubNibbles',
        operation: 'SubNibbles',
        round: 2,
        stateBefore: before,
        stateAfter: cloneState(state)
    });

    // ShiftRows
    before = cloneState(state);
    state = applyShiftRows(state);
    log.steps.push({
        name: 'Round 2 — ShiftRows',
        operation: 'ShiftRows',
        round: 2,
        stateBefore: before,
        stateAfter: cloneState(state)
    });

    // AddRoundKey K2
    before = cloneState(state);
    state = applyAddRoundKey(state, K2);
    log.steps.push({
        name: 'Round 2 — AddRoundKey',
        operation: 'AddRoundKey (K2)',
        round: 2,
        stateBefore: before,
        stateAfter: cloneState(state),
        key: K2,
        keyState: binaryToState(word16ToBin(K2))
    });

    log.result = {
        binary: stateToBinary(state),
        hex: stateToHex(state)
    };

    return log;
}

/**
 * Decrypt a 16-bit ciphertext with a 16-bit key using S-AES InvCipher.
 * Order: AddRoundKey(K2) → [InvShiftRows, InvSubNibbles, AddRoundKey(K1), InvMixColumns]
 *        → [InvShiftRows, InvSubNibbles, AddRoundKey(K0)]
 */
function saesDecrypt(ciphertextBin, keyBin) {
    const key16 = parseInt(keyBin, 2);

    const log = {
        mode: 'decrypt',
        input: { ciphertext: ciphertextBin, key: keyBin },
        keyExpansion: null,
        steps: [],
        result: null
    };

    // ---- Key Expansion (same as encryption) ----
    const ke = keyExpansion(key16);
    log.keyExpansion = ke.log;
    const [K0, K1, K2] = ke.keys;

    // ---- Convert ciphertext to state ----
    let state = binaryToState(ciphertextBin);

    // ---- Initial AddRoundKey (K2) ----
    let before = cloneState(state);
    state = applyAddRoundKey(state, K2);
    log.steps.push({
        name: 'Initial AddRoundKey',
        operation: 'AddRoundKey (K2)',
        stateBefore: before,
        stateAfter: cloneState(state),
        key: K2,
        keyState: binaryToState(word16ToBin(K2))
    });

    // ---- Inverse Round 1 ----
    // InvShiftRows
    before = cloneState(state);
    state = applyInvShiftRows(state);
    log.steps.push({
        name: 'Inv Round 1 — InvShiftRows',
        operation: 'InvShiftRows',
        round: 1,
        stateBefore: before,
        stateAfter: cloneState(state)
    });

    // InvSubNibbles
    before = cloneState(state);
    state = applyInvSubNibbles(state);
    log.steps.push({
        name: 'Inv Round 1 — InvSubNibbles',
        operation: 'InvSubNibbles',
        round: 1,
        stateBefore: before,
        stateAfter: cloneState(state)
    });

    // AddRoundKey K1
    before = cloneState(state);
    state = applyAddRoundKey(state, K1);
    log.steps.push({
        name: 'Inv Round 1 — AddRoundKey',
        operation: 'AddRoundKey (K1)',
        round: 1,
        stateBefore: before,
        stateAfter: cloneState(state),
        key: K1,
        keyState: binaryToState(word16ToBin(K1))
    });

    // InvMixColumns
    before = cloneState(state);
    const imc = applyInvMixColumns(state);
    state = imc.state;
    log.steps.push({
        name: 'Inv Round 1 — InvMixColumns',
        operation: 'InvMixColumns',
        round: 1,
        stateBefore: before,
        stateAfter: cloneState(state),
        gfDetails: imc.details
    });

    // ---- Inverse Round 2 ----
    // InvShiftRows
    before = cloneState(state);
    state = applyInvShiftRows(state);
    log.steps.push({
        name: 'Inv Round 2 — InvShiftRows',
        operation: 'InvShiftRows',
        round: 2,
        stateBefore: before,
        stateAfter: cloneState(state)
    });

    // InvSubNibbles
    before = cloneState(state);
    state = applyInvSubNibbles(state);
    log.steps.push({
        name: 'Inv Round 2 — InvSubNibbles',
        operation: 'InvSubNibbles',
        round: 2,
        stateBefore: before,
        stateAfter: cloneState(state)
    });

    // AddRoundKey K0
    before = cloneState(state);
    state = applyAddRoundKey(state, K0);
    log.steps.push({
        name: 'Inv Round 2 — AddRoundKey',
        operation: 'AddRoundKey (K0)',
        round: 2,
        stateBefore: before,
        stateAfter: cloneState(state),
        key: K0,
        keyState: binaryToState(word16ToBin(K0))
    });

    log.result = {
        binary: stateToBinary(state),
        hex: stateToHex(state)
    };

    return log;
}
