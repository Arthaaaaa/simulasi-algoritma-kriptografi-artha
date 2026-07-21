/**
 * DES (Data Encryption Standard) Core Implementation
 * 
 * Parameters:
 * - Block size: 64 bits
 * - Key size: 64 bits (56 effective)
 * - Rounds: 16 Feistel rounds
 * 
 * Reference: FIPS PUB 46-3
 */

// =====================================================
// CONSTANTS / PERMUTATION TABLES
// =====================================================

// Initial Permutation (IP)
const DES_IP = [
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
];

// Final Permutation (IP^-1)
const DES_FP = [
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41, 9,49,17,57,25
];

// Expansion Permutation (E)
const DES_E = [
    32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32, 1
];

// Permutation (P)
const DES_P = [
    16, 7,20,21,29,12,28,17,
     1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9,
    19,13,30, 6,22,11, 4,25
];

// Permuted Choice 1 (PC-1)
const DES_PC1 = [
    57,49,41,33,25,17, 9,
     1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27,
    19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15,
     7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29,
    21,13, 5,28,20,12, 4
];

// Permuted Choice 2 (PC-2)
const DES_PC2 = [
    14,17,11,24, 1, 5,
     3,28,15, 6,21,10,
    23,19,12, 4,26, 8,
    16, 7,27,20,13, 2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
];

// Left shift schedule per round
const DES_SHIFT_SCHEDULE = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

// S-Boxes (8 boxes, each 4×16)
const DES_SBOX = [
    // S1
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
    ],
    // S2
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
    ],
    // S3
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
    ],
    // S4
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
    ],
    // S5
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
    ],
    // S6
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
    ],
    // S7
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
    ],
    // S8
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,2,0,14,9,11],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
    ]
];

// =====================================================
// UTILITY FUNCTIONS
// =====================================================

function desPermute(bits, table) {
    return table.map(pos => bits[pos - 1]);
}

function desXOR(a, b) {
    return a.map((bit, i) => bit ^ b[i]);
}

function desLeftShift(bits, n) {
    const result = [...bits];
    for (let i = 0; i < n; i++) {
        result.push(result.shift());
    }
    return result;
}

function desBitsToBin(bits) {
    return bits.join('');
}

function desBinToBits(binStr) {
    return binStr.split('').map(Number);
}

function desHexToBits(hexStr) {
    let bin = '';
    for (let i = 0; i < hexStr.length; i++) {
        bin += parseInt(hexStr[i], 16).toString(2).padStart(4, '0');
    }
    return bin.split('').map(Number);
}

function desBitsToHex(bits) {
    let hex = '';
    for (let i = 0; i < bits.length; i += 4) {
        const nibble = bits.slice(i, i + 4);
        hex += parseInt(nibble.join(''), 2).toString(16).toUpperCase();
    }
    return hex;
}

/** Detect if input is hex or binary and convert to 64-bit array */
function desParseInput(input, bitLength) {
    const clean = input.replace(/\s+/g, '');
    if (/^[01]+$/.test(clean)) {
        // Binary
        if (clean.length !== bitLength) return null;
        return desBinToBits(clean);
    } else if (/^[0-9a-fA-F]+$/.test(clean)) {
        // Hex
        if (clean.length !== bitLength / 4) return null;
        return desHexToBits(clean);
    }
    return null;
}

// =====================================================
// KEY GENERATION
// =====================================================

function desKeyGeneration(keyBits) {
    const log = { steps: [], subkeys: [] };

    log.steps.push({
        desc: 'Input Key (64-bit)',
        binary: desBitsToBin(keyBits),
        hex: desBitsToHex(keyBits)
    });

    // PC-1: 64→56 bits
    const afterPC1 = desPermute(keyBits, DES_PC1);
    log.steps.push({
        desc: 'After PC-1 (64→56 bits)',
        binary: desBitsToBin(afterPC1),
        hex: desBitsToHex(afterPC1)
    });

    let C = afterPC1.slice(0, 28);
    let D = afterPC1.slice(28, 56);

    log.steps.push({
        desc: 'Split into C₀ and D₀ (28-bit each)',
        C: desBitsToBin(C),
        D: desBitsToBin(D)
    });

    const subkeys = [];
    const roundDetails = [];

    for (let i = 0; i < 16; i++) {
        const shift = DES_SHIFT_SCHEDULE[i];
        C = desLeftShift(C, shift);
        D = desLeftShift(D, shift);

        const combined = [...C, ...D];
        const Ki = desPermute(combined, DES_PC2);
        subkeys.push(Ki);

        roundDetails.push({
            round: i + 1,
            shift: shift,
            C: desBitsToBin(C),
            D: desBitsToBin(D),
            Ki: desBitsToBin(Ki),
            KiHex: desBitsToHex(Ki)
        });
    }

    log.roundDetails = roundDetails;
    log.subkeys = subkeys;

    return log;
}

// =====================================================
// FEISTEL FUNCTION
// =====================================================

function desFeistelFunction(R, Ki, roundNum) {
    const log = {};

    // Expansion E (32→48)
    const expanded = desPermute(R, DES_E);
    log.expansion = {
        input: desBitsToBin(R),
        output: desBitsToBin(expanded)
    };

    // XOR with subkey
    const xored = desXOR(expanded, Ki);
    log.xorKey = {
        expanded: desBitsToBin(expanded),
        key: desBitsToBin(Ki),
        result: desBitsToBin(xored)
    };

    // S-Box substitution (48→32)
    const sboxOutput = [];
    const sboxDetails = [];

    for (let j = 0; j < 8; j++) {
        const block = xored.slice(j * 6, j * 6 + 6);
        const row = (block[0] << 1) | block[5];
        const col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4];
        const val = DES_SBOX[j][row][col];
        const valBits = [(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1];
        sboxOutput.push(...valBits);

        sboxDetails.push({
            box: j + 1,
            input: desBitsToBin(block),
            row: row,
            col: col,
            value: val,
            output: desBitsToBin(valBits)
        });
    }

    log.sbox = sboxDetails;
    log.sboxCombined = desBitsToBin(sboxOutput);

    // Permutation P (32→32)
    const afterP = desPermute(sboxOutput, DES_P);
    log.permP = {
        input: desBitsToBin(sboxOutput),
        output: desBitsToBin(afterP)
    };

    return { result: afterP, log };
}

// =====================================================
// MAIN ENCRYPT / DECRYPT
// =====================================================

function desEncrypt(plaintextBits, keyBits) {
    const log = {
        mode: 'encrypt',
        input: {
            plaintext: desBitsToBin(plaintextBits),
            plaintextHex: desBitsToHex(plaintextBits),
            key: desBitsToBin(keyBits),
            keyHex: desBitsToHex(keyBits)
        },
        keyGeneration: null,
        steps: [],
        result: null
    };

    // Key Generation
    const kg = desKeyGeneration(keyBits);
    log.keyGeneration = kg;

    // Initial Permutation
    const afterIP = desPermute(plaintextBits, DES_IP);
    log.steps.push({
        name: 'Initial Permutation (IP)',
        operation: 'IP',
        input: desBitsToBin(plaintextBits),
        inputHex: desBitsToHex(plaintextBits),
        output: desBitsToBin(afterIP),
        outputHex: desBitsToHex(afterIP)
    });

    let L = afterIP.slice(0, 32);
    let R = afterIP.slice(32, 64);

    // 16 Feistel Rounds
    for (let i = 0; i < 16; i++) {
        const Ki = kg.subkeys[i];
        const f = desFeistelFunction(R, Ki, i + 1);
        const newR = desXOR(L, f.result);
        const oldL = L;
        L = R;
        const oldR = R;
        R = newR;

        log.steps.push({
            name: `Round ${i + 1}`,
            operation: 'Feistel',
            round: i + 1,
            subkey: desBitsToBin(Ki),
            subkeyHex: desBitsToHex(Ki),
            L_in: desBitsToBin(oldL),
            R_in: desBitsToBin(oldR),
            L_inHex: desBitsToHex(oldL),
            R_inHex: desBitsToHex(oldR),
            feistelLog: f.log,
            feistelResult: desBitsToBin(f.result),
            L_out: desBitsToBin(L),
            R_out: desBitsToBin(R),
            L_outHex: desBitsToHex(L),
            R_outHex: desBitsToHex(R)
        });
    }

    // Combine R16L16 (swap before final permutation)
    const combined = [...R, ...L];
    log.steps.push({
        name: 'Pre-output (R₁₆L₁₆)',
        operation: 'Combine',
        value: desBitsToBin(combined),
        hex: desBitsToHex(combined)
    });

    // Final Permutation
    const afterFP = desPermute(combined, DES_FP);
    log.steps.push({
        name: 'Final Permutation (IP⁻¹)',
        operation: 'FP',
        input: desBitsToBin(combined),
        output: desBitsToBin(afterFP),
        outputHex: desBitsToHex(afterFP)
    });

    log.result = {
        binary: desBitsToBin(afterFP),
        hex: desBitsToHex(afterFP)
    };

    return log;
}

function desDecrypt(ciphertextBits, keyBits) {
    const log = {
        mode: 'decrypt',
        input: {
            ciphertext: desBitsToBin(ciphertextBits),
            ciphertextHex: desBitsToHex(ciphertextBits),
            key: desBitsToBin(keyBits),
            keyHex: desBitsToHex(keyBits)
        },
        keyGeneration: null,
        steps: [],
        result: null
    };

    // Key Generation (same as encrypt, but subkeys used in reverse)
    const kg = desKeyGeneration(keyBits);
    log.keyGeneration = kg;

    // Initial Permutation
    const afterIP = desPermute(ciphertextBits, DES_IP);
    log.steps.push({
        name: 'Initial Permutation (IP)',
        operation: 'IP',
        input: desBitsToBin(ciphertextBits),
        inputHex: desBitsToHex(ciphertextBits),
        output: desBitsToBin(afterIP),
        outputHex: desBitsToHex(afterIP)
    });

    let L = afterIP.slice(0, 32);
    let R = afterIP.slice(32, 64);

    // 16 Feistel Rounds (keys in reverse order)
    for (let i = 0; i < 16; i++) {
        const Ki = kg.subkeys[15 - i]; // reverse order
        const f = desFeistelFunction(R, Ki, i + 1);
        const newR = desXOR(L, f.result);
        const oldL = L;
        const oldR = R;
        L = R;
        R = newR;

        log.steps.push({
            name: `Round ${i + 1} (K${16 - i})`,
            operation: 'Feistel',
            round: i + 1,
            subkey: desBitsToBin(Ki),
            subkeyHex: desBitsToHex(Ki),
            L_in: desBitsToBin(oldL),
            R_in: desBitsToBin(oldR),
            L_inHex: desBitsToHex(oldL),
            R_inHex: desBitsToHex(oldR),
            feistelLog: f.log,
            feistelResult: desBitsToBin(f.result),
            L_out: desBitsToBin(L),
            R_out: desBitsToBin(R),
            L_outHex: desBitsToHex(L),
            R_outHex: desBitsToHex(R)
        });
    }

    // Combine R16L16
    const combined = [...R, ...L];
    log.steps.push({
        name: 'Pre-output (R₁₆L₁₆)',
        operation: 'Combine',
        value: desBitsToBin(combined),
        hex: desBitsToHex(combined)
    });

    // Final Permutation
    const afterFP = desPermute(combined, DES_FP);
    log.steps.push({
        name: 'Final Permutation (IP⁻¹)',
        operation: 'FP',
        input: desBitsToBin(combined),
        output: desBitsToBin(afterFP),
        outputHex: desBitsToHex(afterFP)
    });

    log.result = {
        binary: desBitsToBin(afterFP),
        hex: desBitsToHex(afterFP)
    };

    return log;
}
