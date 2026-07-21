/**
 * S-DES (Simplified Data Encryption Standard) Core Implementation
 * 
 * Parameters:
 * - Block size: 8 bits
 * - Key size: 10 bits
 * - Rounds: 2 Feistel rounds
 * 
 * Reference: Stallings, W. "Cryptography and Network Security"
 */

// =====================================================
// CONSTANTS / PERMUTATION TABLES
// =====================================================

const SDES_P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
const SDES_P8  = [6, 3, 7, 4, 8, 5, 10, 9];
const SDES_IP  = [2, 6, 3, 1, 4, 8, 5, 7];
const SDES_IP_INV = [4, 1, 3, 5, 7, 2, 8, 6];
const SDES_EP  = [4, 1, 2, 3, 2, 3, 4, 1];
const SDES_P4  = [2, 4, 3, 1];

const SDES_S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
];

const SDES_S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
];

// =====================================================
// UTILITY FUNCTIONS
// =====================================================

function sdesBitsToBin(bits) {
    return bits.join('');
}

function sdesBinToBits(binStr) {
    return binStr.split('').map(Number);
}

function sdesPermute(bits, table) {
    return table.map(pos => bits[pos - 1]);
}

function sdesXOR(a, b) {
    return a.map((bit, i) => bit ^ b[i]);
}

function sdesLeftShift(bits, n) {
    const result = [...bits];
    for (let i = 0; i < n; i++) {
        result.push(result.shift());
    }
    return result;
}

// =====================================================
// KEY GENERATION
// =====================================================

function sdesKeyGeneration(keyBin) {
    const log = { steps: [], K1: null, K2: null };
    const keyBits = sdesBinToBits(keyBin);

    log.steps.push({
        desc: 'Input Key (10-bit)',
        value: sdesBitsToBin(keyBits)
    });

    // P10
    const afterP10 = sdesPermute(keyBits, SDES_P10);
    log.steps.push({
        desc: 'After P10 Permutation',
        detail: `P10 = [${SDES_P10.join(', ')}]`,
        input: sdesBitsToBin(keyBits),
        output: sdesBitsToBin(afterP10)
    });

    // Split into left and right halves (5 bits each)
    const left0 = afterP10.slice(0, 5);
    const right0 = afterP10.slice(5, 10);
    log.steps.push({
        desc: 'Split into 5-bit halves',
        left: sdesBitsToBin(left0),
        right: sdesBitsToBin(right0)
    });

    // LS-1 (Left Shift by 1)
    const left1 = sdesLeftShift(left0, 1);
    const right1 = sdesLeftShift(right0, 1);
    log.steps.push({
        desc: 'Left Shift-1 (LS-1)',
        leftIn: sdesBitsToBin(left0),
        leftOut: sdesBitsToBin(left1),
        rightIn: sdesBitsToBin(right0),
        rightOut: sdesBitsToBin(right1)
    });

    // P8 → K1
    const combined1 = [...left1, ...right1];
    const K1 = sdesPermute(combined1, SDES_P8);
    log.steps.push({
        desc: 'P8 Permutation → K1',
        detail: `P8 = [${SDES_P8.join(', ')}]`,
        input: sdesBitsToBin(combined1),
        output: sdesBitsToBin(K1)
    });

    // LS-2 (Left Shift by 2 from LS-1 result)
    const left2 = sdesLeftShift(left1, 2);
    const right2 = sdesLeftShift(right1, 2);
    log.steps.push({
        desc: 'Left Shift-2 (LS-2)',
        leftIn: sdesBitsToBin(left1),
        leftOut: sdesBitsToBin(left2),
        rightIn: sdesBitsToBin(right1),
        rightOut: sdesBitsToBin(right2)
    });

    // P8 → K2
    const combined2 = [...left2, ...right2];
    const K2 = sdesPermute(combined2, SDES_P8);
    log.steps.push({
        desc: 'P8 Permutation → K2',
        detail: `P8 = [${SDES_P8.join(', ')}]`,
        input: sdesBitsToBin(combined2),
        output: sdesBitsToBin(K2)
    });

    log.K1 = K1;
    log.K2 = K2;

    return log;
}

// =====================================================
// FEISTEL FUNCTION (fK)
// =====================================================

function sdesSBoxLookup(bits4, sbox) {
    const row = (bits4[0] << 1) | bits4[3]; // first & last bit
    const col = (bits4[1] << 1) | bits4[2]; // middle two bits
    const val = sbox[row][col];
    return [(val >> 1) & 1, val & 1];
}

function sdesFeistel(rightBits, subkey) {
    const log = {};

    // E/P (Expansion Permutation)
    const expanded = sdesPermute(rightBits, SDES_EP);
    log.ep = { input: sdesBitsToBin(rightBits), output: sdesBitsToBin(expanded) };

    // XOR with subkey
    const xored = sdesXOR(expanded, subkey);
    log.xor = {
        a: sdesBitsToBin(expanded),
        b: sdesBitsToBin(subkey),
        result: sdesBitsToBin(xored)
    };

    // Split into two 4-bit halves
    const xorLeft = xored.slice(0, 4);
    const xorRight = xored.slice(4, 8);

    // S-Box S0 and S1
    const s0Result = sdesSBoxLookup(xorLeft, SDES_S0);
    const s1Result = sdesSBoxLookup(xorRight, SDES_S1);

    log.sbox = {
        s0: {
            input: sdesBitsToBin(xorLeft),
            row: (xorLeft[0] << 1) | xorLeft[3],
            col: (xorLeft[1] << 1) | xorLeft[2],
            output: sdesBitsToBin(s0Result)
        },
        s1: {
            input: sdesBitsToBin(xorRight),
            row: (xorRight[0] << 1) | xorRight[3],
            col: (xorRight[1] << 1) | xorRight[2],
            output: sdesBitsToBin(s1Result)
        }
    };

    // P4
    const sboxCombined = [...s0Result, ...s1Result];
    const afterP4 = sdesPermute(sboxCombined, SDES_P4);
    log.p4 = { input: sdesBitsToBin(sboxCombined), output: sdesBitsToBin(afterP4) };

    return { result: afterP4, log };
}

// =====================================================
// MAIN ENCRYPT / DECRYPT
// =====================================================

function sdesEncrypt(plaintextBin, keyBin) {
    const log = {
        mode: 'encrypt',
        input: { plaintext: plaintextBin, key: keyBin },
        keyGeneration: null,
        steps: [],
        result: null
    };

    // Key Generation
    const kg = sdesKeyGeneration(keyBin);
    log.keyGeneration = kg;
    const K1 = kg.K1;
    const K2 = kg.K2;

    const plainBits = sdesBinToBits(plaintextBin);

    // Initial Permutation
    const afterIP = sdesPermute(plainBits, SDES_IP);
    log.steps.push({
        name: 'Initial Permutation (IP)',
        operation: 'IP',
        detail: `IP = [${SDES_IP.join(', ')}]`,
        input: sdesBitsToBin(plainBits),
        output: sdesBitsToBin(afterIP)
    });

    // Split
    let left = afterIP.slice(0, 4);
    let right = afterIP.slice(4, 8);
    log.steps.push({
        name: 'Split after IP',
        operation: 'Split',
        left: sdesBitsToBin(left),
        right: sdesBitsToBin(right)
    });

    // Round 1: fK with K1
    const f1 = sdesFeistel(right, K1);
    const xorLeft1 = sdesXOR(left, f1.result);

    log.steps.push({
        name: 'Round 1 — Feistel Function (K1)',
        operation: 'Round',
        round: 1,
        subkey: sdesBitsToBin(K1),
        feistelLog: f1.log,
        leftBefore: sdesBitsToBin(left),
        rightBefore: sdesBitsToBin(right),
        feistelResult: sdesBitsToBin(f1.result),
        xorWithLeft: sdesBitsToBin(xorLeft1),
        newLeft: sdesBitsToBin(xorLeft1),
        newRight: sdesBitsToBin(right)
    });

    // Swap (SW)
    const swapLeft = right;
    const swapRight = xorLeft1;
    log.steps.push({
        name: 'Swap (SW)',
        operation: 'Swap',
        before: sdesBitsToBin(xorLeft1) + sdesBitsToBin(right),
        after: sdesBitsToBin(swapLeft) + sdesBitsToBin(swapRight),
        left: sdesBitsToBin(swapLeft),
        right: sdesBitsToBin(swapRight)
    });

    // Round 2: fK with K2
    const f2 = sdesFeistel(swapRight, K2);
    const xorLeft2 = sdesXOR(swapLeft, f2.result);

    log.steps.push({
        name: 'Round 2 — Feistel Function (K2)',
        operation: 'Round',
        round: 2,
        subkey: sdesBitsToBin(K2),
        feistelLog: f2.log,
        leftBefore: sdesBitsToBin(swapLeft),
        rightBefore: sdesBitsToBin(swapRight),
        feistelResult: sdesBitsToBin(f2.result),
        xorWithLeft: sdesBitsToBin(xorLeft2),
        newLeft: sdesBitsToBin(xorLeft2),
        newRight: sdesBitsToBin(swapRight)
    });

    // Combine (no swap after Round 2)
    const combined = [...xorLeft2, ...swapRight];

    // Final Permutation (IP^-1)
    const afterIPInv = sdesPermute(combined, SDES_IP_INV);
    log.steps.push({
        name: 'Final Permutation (IP⁻¹)',
        operation: 'IP_INV',
        detail: `IP⁻¹ = [${SDES_IP_INV.join(', ')}]`,
        input: sdesBitsToBin(combined),
        output: sdesBitsToBin(afterIPInv)
    });

    log.result = sdesBitsToBin(afterIPInv);

    return log;
}

function sdesDecrypt(ciphertextBin, keyBin) {
    const log = {
        mode: 'decrypt',
        input: { ciphertext: ciphertextBin, key: keyBin },
        keyGeneration: null,
        steps: [],
        result: null
    };

    // Key Generation
    const kg = sdesKeyGeneration(keyBin);
    log.keyGeneration = kg;
    const K1 = kg.K1;
    const K2 = kg.K2;

    const cipherBits = sdesBinToBits(ciphertextBin);

    // Initial Permutation
    const afterIP = sdesPermute(cipherBits, SDES_IP);
    log.steps.push({
        name: 'Initial Permutation (IP)',
        operation: 'IP',
        detail: `IP = [${SDES_IP.join(', ')}]`,
        input: sdesBitsToBin(cipherBits),
        output: sdesBitsToBin(afterIP)
    });

    // Split
    let left = afterIP.slice(0, 4);
    let right = afterIP.slice(4, 8);
    log.steps.push({
        name: 'Split after IP',
        operation: 'Split',
        left: sdesBitsToBin(left),
        right: sdesBitsToBin(right)
    });

    // Round 1: fK with K2 (reversed key order)
    const f1 = sdesFeistel(right, K2);
    const xorLeft1 = sdesXOR(left, f1.result);

    log.steps.push({
        name: 'Round 1 — Feistel Function (K2)',
        operation: 'Round',
        round: 1,
        subkey: sdesBitsToBin(K2),
        feistelLog: f1.log,
        leftBefore: sdesBitsToBin(left),
        rightBefore: sdesBitsToBin(right),
        feistelResult: sdesBitsToBin(f1.result),
        xorWithLeft: sdesBitsToBin(xorLeft1),
        newLeft: sdesBitsToBin(xorLeft1),
        newRight: sdesBitsToBin(right)
    });

    // Swap (SW)
    const swapLeft = right;
    const swapRight = xorLeft1;
    log.steps.push({
        name: 'Swap (SW)',
        operation: 'Swap',
        before: sdesBitsToBin(xorLeft1) + sdesBitsToBin(right),
        after: sdesBitsToBin(swapLeft) + sdesBitsToBin(swapRight),
        left: sdesBitsToBin(swapLeft),
        right: sdesBitsToBin(swapRight)
    });

    // Round 2: fK with K1 (reversed key order)
    const f2 = sdesFeistel(swapRight, K1);
    const xorLeft2 = sdesXOR(swapLeft, f2.result);

    log.steps.push({
        name: 'Round 2 — Feistel Function (K1)',
        operation: 'Round',
        round: 2,
        subkey: sdesBitsToBin(K1),
        feistelLog: f2.log,
        leftBefore: sdesBitsToBin(swapLeft),
        rightBefore: sdesBitsToBin(swapRight),
        feistelResult: sdesBitsToBin(f2.result),
        xorWithLeft: sdesBitsToBin(xorLeft2),
        newLeft: sdesBitsToBin(xorLeft2),
        newRight: sdesBitsToBin(swapRight)
    });

    // Combine (no swap after Round 2)
    const combined = [...xorLeft2, ...swapRight];

    // Final Permutation (IP^-1)
    const afterIPInv = sdesPermute(combined, SDES_IP_INV);
    log.steps.push({
        name: 'Final Permutation (IP⁻¹)',
        operation: 'IP_INV',
        detail: `IP⁻¹ = [${SDES_IP_INV.join(', ')}]`,
        input: sdesBitsToBin(combined),
        output: sdesBitsToBin(afterIPInv)
    });

    log.result = sdesBitsToBin(afterIPInv);

    return log;
}
