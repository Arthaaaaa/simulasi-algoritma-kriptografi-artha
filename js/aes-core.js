/**
 * AES-128 (Advanced Encryption Standard) Core Implementation
 * 
 * Parameters:
 * - Block size: 128 bits (4×4 byte state matrix)
 * - Key size: 128 bits
 * - Rounds: 10
 * - Field: GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
 * 
 * Reference: FIPS PUB 197
 */

// =====================================================
// CONSTANTS
// =====================================================

const AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
];

const AES_INV_SBOX = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
];

const AES_RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

// =====================================================
// GF(2^8) ARITHMETIC
// =====================================================

function aesGfMul(a, b) {
    let result = 0;
    let tempA = a;
    let tempB = b;
    for (let i = 0; i < 8; i++) {
        if (tempB & 1) result ^= tempA;
        tempB >>= 1;
        const hiBit = tempA & 0x80;
        tempA = (tempA << 1) & 0xFF;
        if (hiBit) tempA ^= 0x1B;
    }
    return result;
}

// =====================================================
// UTILITY FUNCTIONS
// =====================================================

function aesByteToHex(b) {
    return (b & 0xFF).toString(16).toUpperCase().padStart(2, '0');
}

function aesHexToByte(hex) {
    return parseInt(hex, 16) & 0xFF;
}

/** Parse 32 hex chars into 4×4 state matrix (column-major) */
function aesHexToState(hexStr) {
    const state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let col = 0; col < 4; col++) {
        for (let row = 0; row < 4; row++) {
            state[row][col] = parseInt(hexStr.substr((col * 4 + row) * 2, 2), 16);
        }
    }
    return state;
}

/** Convert 4×4 state matrix to hex string (column-major) */
function aesStateToHex(state) {
    let hex = '';
    for (let col = 0; col < 4; col++) {
        for (let row = 0; row < 4; row++) {
            hex += aesByteToHex(state[row][col]);
        }
    }
    return hex;
}

function aesCloneState(state) {
    return state.map(row => [...row]);
}

function aesStateToDisplay(state) {
    return state.map(row => row.map(b => aesByteToHex(b)));
}

// =====================================================
// KEY EXPANSION
// =====================================================

function aesKeyExpansion(keyHex) {
    const log = { steps: [], roundKeys: [] };

    // Parse key into 4 words (each 4 bytes)
    const w = [];
    for (let i = 0; i < 4; i++) {
        w.push([
            aesHexToByte(keyHex.substr(i * 8, 2)),
            aesHexToByte(keyHex.substr(i * 8 + 2, 2)),
            aesHexToByte(keyHex.substr(i * 8 + 4, 2)),
            aesHexToByte(keyHex.substr(i * 8 + 6, 2))
        ]);
    }

    log.steps.push({
        desc: 'Initial Key Words',
        words: w.slice(0, 4).map((word, i) => ({
            name: `w[${i}]`,
            value: word.map(b => aesByteToHex(b)).join('')
        }))
    });

    // Generate words w[4] to w[43]
    for (let i = 4; i < 44; i++) {
        let temp = [...w[i - 1]];
        const stepLog = { wordIndex: i };

        if (i % 4 === 0) {
            const roundIdx = (i / 4) - 1;

            // RotWord
            const rotted = [temp[1], temp[2], temp[3], temp[0]];
            stepLog.rotWord = {
                input: temp.map(b => aesByteToHex(b)).join(''),
                output: rotted.map(b => aesByteToHex(b)).join('')
            };

            // SubWord
            const subbed = rotted.map(b => AES_SBOX[b]);
            stepLog.subWord = {
                input: rotted.map(b => aesByteToHex(b)).join(''),
                output: subbed.map(b => aesByteToHex(b)).join('')
            };

            // XOR with Rcon
            const rcon = [AES_RCON[roundIdx], 0, 0, 0];
            temp = subbed.map((b, j) => b ^ rcon[j]);
            stepLog.rcon = {
                value: rcon.map(b => aesByteToHex(b)).join(''),
                result: temp.map(b => aesByteToHex(b)).join('')
            };
        }

        // w[i] = w[i-4] XOR temp
        const newWord = w[i - 4].map((b, j) => b ^ temp[j]);
        stepLog.xor = {
            wi4: w[i - 4].map(b => aesByteToHex(b)).join(''),
            temp: temp.map(b => aesByteToHex(b)).join(''),
            result: newWord.map(b => aesByteToHex(b)).join('')
        };

        w.push(newWord);
        if (i % 4 === 0) {
            log.steps.push(stepLog);
        }
    }

    // Extract round keys as state matrices
    for (let round = 0; round <= 10; round++) {
        const key = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
        for (let col = 0; col < 4; col++) {
            const word = w[round * 4 + col];
            for (let row = 0; row < 4; row++) {
                key[row][col] = word[row];
            }
        }
        log.roundKeys.push(key);
    }

    log.allWords = w;

    return log;
}

// =====================================================
// STATE TRANSFORMATIONS — ENCRYPTION
// =====================================================

function aesSubBytes(state) {
    return state.map(row => row.map(b => AES_SBOX[b]));
}

function aesShiftRows(state) {
    const result = aesCloneState(state);
    // Row 0: no shift
    // Row 1: shift left 1
    const r1 = [state[1][1], state[1][2], state[1][3], state[1][0]];
    // Row 2: shift left 2
    const r2 = [state[2][2], state[2][3], state[2][0], state[2][1]];
    // Row 3: shift left 3
    const r3 = [state[3][3], state[3][0], state[3][1], state[3][2]];
    result[1] = r1;
    result[2] = r2;
    result[3] = r3;
    return result;
}

function aesMixColumns(state) {
    const result = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let c = 0; c < 4; c++) {
        result[0][c] = aesGfMul(2, state[0][c]) ^ aesGfMul(3, state[1][c]) ^ state[2][c] ^ state[3][c];
        result[1][c] = state[0][c] ^ aesGfMul(2, state[1][c]) ^ aesGfMul(3, state[2][c]) ^ state[3][c];
        result[2][c] = state[0][c] ^ state[1][c] ^ aesGfMul(2, state[2][c]) ^ aesGfMul(3, state[3][c]);
        result[3][c] = aesGfMul(3, state[0][c]) ^ state[1][c] ^ state[2][c] ^ aesGfMul(2, state[3][c]);
    }
    return result;
}

function aesAddRoundKey(state, roundKey) {
    const result = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let r = 0; r < 4; r++) {
        for (let c = 0; c < 4; c++) {
            result[r][c] = state[r][c] ^ roundKey[r][c];
        }
    }
    return result;
}

// =====================================================
// STATE TRANSFORMATIONS — DECRYPTION
// =====================================================

function aesInvSubBytes(state) {
    return state.map(row => row.map(b => AES_INV_SBOX[b]));
}

function aesInvShiftRows(state) {
    const result = aesCloneState(state);
    // Row 1: shift right 1
    result[1] = [state[1][3], state[1][0], state[1][1], state[1][2]];
    // Row 2: shift right 2
    result[2] = [state[2][2], state[2][3], state[2][0], state[2][1]];
    // Row 3: shift right 3
    result[3] = [state[3][1], state[3][2], state[3][3], state[3][0]];
    return result;
}

function aesInvMixColumns(state) {
    const result = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let c = 0; c < 4; c++) {
        result[0][c] = aesGfMul(14,state[0][c])^aesGfMul(11,state[1][c])^aesGfMul(13,state[2][c])^aesGfMul(9,state[3][c]);
        result[1][c] = aesGfMul(9,state[0][c])^aesGfMul(14,state[1][c])^aesGfMul(11,state[2][c])^aesGfMul(13,state[3][c]);
        result[2][c] = aesGfMul(13,state[0][c])^aesGfMul(9,state[1][c])^aesGfMul(14,state[2][c])^aesGfMul(11,state[3][c]);
        result[3][c] = aesGfMul(11,state[0][c])^aesGfMul(13,state[1][c])^aesGfMul(9,state[2][c])^aesGfMul(14,state[3][c]);
    }
    return result;
}

// =====================================================
// MAIN ENCRYPT / DECRYPT
// =====================================================

function aesEncrypt(plaintextHex, keyHex) {
    const log = {
        mode: 'encrypt',
        input: { plaintext: plaintextHex.toUpperCase(), key: keyHex.toUpperCase() },
        keyExpansion: null,
        steps: [],
        result: null
    };

    // Key Expansion
    const ke = aesKeyExpansion(keyHex);
    log.keyExpansion = ke;

    // Parse plaintext to state
    let state = aesHexToState(plaintextHex);

    // Initial AddRoundKey (Round 0)
    let before = aesCloneState(state);
    state = aesAddRoundKey(state, ke.roundKeys[0]);
    log.steps.push({
        name: 'Initial AddRoundKey (Round 0)',
        operation: 'AddRoundKey',
        round: 0,
        stateBefore: aesStateToDisplay(before),
        roundKey: aesStateToDisplay(ke.roundKeys[0]),
        stateAfter: aesStateToDisplay(state)
    });

    // Rounds 1–9
    for (let r = 1; r <= 9; r++) {
        const roundSteps = { round: r, substeps: [] };

        // SubBytes
        before = aesCloneState(state);
        state = aesSubBytes(state);
        roundSteps.substeps.push({
            name: `Round ${r} — SubBytes`,
            operation: 'SubBytes',
            stateBefore: aesStateToDisplay(before),
            stateAfter: aesStateToDisplay(state)
        });

        // ShiftRows
        before = aesCloneState(state);
        state = aesShiftRows(state);
        roundSteps.substeps.push({
            name: `Round ${r} — ShiftRows`,
            operation: 'ShiftRows',
            stateBefore: aesStateToDisplay(before),
            stateAfter: aesStateToDisplay(state)
        });

        // MixColumns
        before = aesCloneState(state);
        state = aesMixColumns(state);
        roundSteps.substeps.push({
            name: `Round ${r} — MixColumns`,
            operation: 'MixColumns',
            stateBefore: aesStateToDisplay(before),
            stateAfter: aesStateToDisplay(state)
        });

        // AddRoundKey
        before = aesCloneState(state);
        state = aesAddRoundKey(state, ke.roundKeys[r]);
        roundSteps.substeps.push({
            name: `Round ${r} — AddRoundKey`,
            operation: 'AddRoundKey',
            stateBefore: aesStateToDisplay(before),
            roundKey: aesStateToDisplay(ke.roundKeys[r]),
            stateAfter: aesStateToDisplay(state)
        });

        log.steps.push(roundSteps);
    }

    // Round 10 (no MixColumns)
    const finalRound = { round: 10, substeps: [] };

    before = aesCloneState(state);
    state = aesSubBytes(state);
    finalRound.substeps.push({
        name: 'Round 10 — SubBytes',
        operation: 'SubBytes',
        stateBefore: aesStateToDisplay(before),
        stateAfter: aesStateToDisplay(state)
    });

    before = aesCloneState(state);
    state = aesShiftRows(state);
    finalRound.substeps.push({
        name: 'Round 10 — ShiftRows',
        operation: 'ShiftRows',
        stateBefore: aesStateToDisplay(before),
        stateAfter: aesStateToDisplay(state)
    });

    before = aesCloneState(state);
    state = aesAddRoundKey(state, ke.roundKeys[10]);
    finalRound.substeps.push({
        name: 'Round 10 — AddRoundKey',
        operation: 'AddRoundKey',
        stateBefore: aesStateToDisplay(before),
        roundKey: aesStateToDisplay(ke.roundKeys[10]),
        stateAfter: aesStateToDisplay(state)
    });

    log.steps.push(finalRound);

    log.result = {
        hex: aesStateToHex(state),
        state: aesStateToDisplay(state)
    };

    return log;
}

function aesDecrypt(ciphertextHex, keyHex) {
    const log = {
        mode: 'decrypt',
        input: { ciphertext: ciphertextHex.toUpperCase(), key: keyHex.toUpperCase() },
        keyExpansion: null,
        steps: [],
        result: null
    };

    const ke = aesKeyExpansion(keyHex);
    log.keyExpansion = ke;

    let state = aesHexToState(ciphertextHex);

    // Initial AddRoundKey (Round 10 key)
    let before = aesCloneState(state);
    state = aesAddRoundKey(state, ke.roundKeys[10]);
    log.steps.push({
        name: 'Initial AddRoundKey (Round Key 10)',
        operation: 'AddRoundKey',
        round: 0,
        stateBefore: aesStateToDisplay(before),
        roundKey: aesStateToDisplay(ke.roundKeys[10]),
        stateAfter: aesStateToDisplay(state)
    });

    // Rounds 9–1
    for (let r = 9; r >= 1; r--) {
        const roundSteps = { round: 10 - r, substeps: [] };

        // InvShiftRows
        before = aesCloneState(state);
        state = aesInvShiftRows(state);
        roundSteps.substeps.push({
            name: `Inv Round ${10-r} — InvShiftRows (Key ${r})`,
            operation: 'InvShiftRows',
            stateBefore: aesStateToDisplay(before),
            stateAfter: aesStateToDisplay(state)
        });

        // InvSubBytes
        before = aesCloneState(state);
        state = aesInvSubBytes(state);
        roundSteps.substeps.push({
            name: `Inv Round ${10-r} — InvSubBytes`,
            operation: 'InvSubBytes',
            stateBefore: aesStateToDisplay(before),
            stateAfter: aesStateToDisplay(state)
        });

        // AddRoundKey
        before = aesCloneState(state);
        state = aesAddRoundKey(state, ke.roundKeys[r]);
        roundSteps.substeps.push({
            name: `Inv Round ${10-r} — AddRoundKey (Key ${r})`,
            operation: 'AddRoundKey',
            stateBefore: aesStateToDisplay(before),
            roundKey: aesStateToDisplay(ke.roundKeys[r]),
            stateAfter: aesStateToDisplay(state)
        });

        // InvMixColumns
        before = aesCloneState(state);
        state = aesInvMixColumns(state);
        roundSteps.substeps.push({
            name: `Inv Round ${10-r} — InvMixColumns`,
            operation: 'InvMixColumns',
            stateBefore: aesStateToDisplay(before),
            stateAfter: aesStateToDisplay(state)
        });

        log.steps.push(roundSteps);
    }

    // Final inverse round (no InvMixColumns)
    const finalRound = { round: 10, substeps: [] };

    before = aesCloneState(state);
    state = aesInvShiftRows(state);
    finalRound.substeps.push({
        name: 'Final Inv Round — InvShiftRows',
        operation: 'InvShiftRows',
        stateBefore: aesStateToDisplay(before),
        stateAfter: aesStateToDisplay(state)
    });

    before = aesCloneState(state);
    state = aesInvSubBytes(state);
    finalRound.substeps.push({
        name: 'Final Inv Round — InvSubBytes',
        operation: 'InvSubBytes',
        stateBefore: aesStateToDisplay(before),
        stateAfter: aesStateToDisplay(state)
    });

    before = aesCloneState(state);
    state = aesAddRoundKey(state, ke.roundKeys[0]);
    finalRound.substeps.push({
        name: 'Final Inv Round — AddRoundKey (Key 0)',
        operation: 'AddRoundKey',
        stateBefore: aesStateToDisplay(before),
        roundKey: aesStateToDisplay(ke.roundKeys[0]),
        stateAfter: aesStateToDisplay(state)
    });

    log.steps.push(finalRound);

    log.result = {
        hex: aesStateToHex(state),
        state: aesStateToDisplay(state)
    };

    return log;
}
