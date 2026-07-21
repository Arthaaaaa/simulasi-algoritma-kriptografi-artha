/**
 * S-DES Simulator — UI Module
 * Renders form, results, and step-by-step details for S-DES.
 */

const SDESModule = (() => {
    let container;

    function init(el) {
        container = el;
        render();
    }

    function render() {
        container.innerHTML = `
            <section class="card input-card" id="sdes-input-section">
                <h2 class="section-title">Input</h2>
                <form id="sdes-form" autocomplete="off">
                    <div class="mode-selector">
                        <label class="mode-option">
                            <input type="radio" name="sdes-mode" value="encrypt" checked>
                            <span class="mode-label">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                                Enkripsi
                            </span>
                        </label>
                        <label class="mode-option">
                            <input type="radio" name="sdes-mode" value="decrypt">
                            <span class="mode-label">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9 1"/></svg>
                                Dekripsi
                            </span>
                        </label>
                    </div>
                    <div class="form-group">
                        <label for="sdes-input" id="sdes-input-label">Plaintext (8-bit biner)</label>
                        <input type="text" id="sdes-input" maxlength="8" placeholder="contoh: 10010111" required>
                        <div class="input-hint">
                            <span>Masukkan tepat 8 digit biner (0 dan 1)</span>
                            <span class="char-counter" id="sdes-input-counter">0/8</span>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="sdes-key">Kunci (10-bit biner)</label>
                        <input type="text" id="sdes-key" maxlength="10" placeholder="contoh: 1010000010" required>
                        <div class="input-hint">
                            <span>Masukkan tepat 10 digit biner (0 dan 1)</span>
                            <span class="char-counter" id="sdes-key-counter">0/10</span>
                        </div>
                    </div>
                    <div class="button-group">
                        <button type="submit" class="btn btn-primary" id="sdes-submit">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                            SUBMIT
                        </button>
                        <button type="button" class="btn btn-secondary" id="sdes-reset">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                            RESET
                        </button>
                    </div>
                </form>
            </section>
            <div class="error-message hidden" id="sdes-error"></div>
            <section class="card result-card hidden" id="sdes-result-section">
                <h2 class="section-title">Hasil</h2>
                <div class="result-display">
                    <div class="result-item">
                        <span class="result-label" id="sdes-result-label">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                            Ciphertext
                        </span>
                        <div class="result-values">
                            <div class="result-value">
                                <span class="value-label">Biner (8-bit)</span>
                                <span class="value-text mono" id="sdes-result-binary"></span>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
            <section class="card steps-card hidden" id="sdes-steps-section">
                <div class="steps-header">
                    <h2 class="section-title">Tampilkan Solusi Penyelesaian</h2>
                    <button type="button" class="btn btn-sm btn-outline" id="sdes-toggle-all">Buka Semua</button>
                </div>
                <div id="sdes-steps-container" class="stagger"></div>
            </section>
        `;
        bindEvents();
    }

    function bindEvents() {
        const form = document.getElementById('sdes-form');
        const inputField = document.getElementById('sdes-input');
        const keyField = document.getElementById('sdes-key');
        const resetBtn = document.getElementById('sdes-reset');
        const toggleAllBtn = document.getElementById('sdes-toggle-all');
        const modeRadios = document.querySelectorAll('input[name="sdes-mode"]');

        setupCounter(inputField, document.getElementById('sdes-input-counter'), 8);
        setupCounter(keyField, document.getElementById('sdes-key-counter'), 10);

        modeRadios.forEach(r => r.addEventListener('change', () => {
            document.getElementById('sdes-input-label').textContent =
                r.value === 'encrypt' ? 'Plaintext (8-bit biner)' : 'Ciphertext (8-bit biner)';
        }));

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            hideError('sdes-error');
            const input = inputField.value.trim();
            const key = keyField.value.trim();
            const mode = document.querySelector('input[name="sdes-mode"]:checked').value;

            if (!/^[01]{8}$/.test(input)) {
                showError('sdes-error', 'Input harus berupa tepat 8 digit biner (0 dan 1).');
                inputField.classList.add('error');
                return;
            }
            if (!/^[01]{10}$/.test(key)) {
                showError('sdes-error', 'Kunci harus berupa tepat 10 digit biner (0 dan 1).');
                keyField.classList.add('error');
                return;
            }

            inputField.classList.remove('error');
            keyField.classList.remove('error');

            const result = mode === 'encrypt' ? sdesEncrypt(input, key) : sdesDecrypt(input, key);
            renderResult(result);
            renderSteps(result);
            document.getElementById('sdes-result-section').scrollIntoView({ behavior: 'smooth' });
        });

        resetBtn.addEventListener('click', () => {
            form.reset();
            inputField.classList.remove('error');
            keyField.classList.remove('error');
            document.getElementById('sdes-result-section').classList.add('hidden');
            document.getElementById('sdes-steps-section').classList.add('hidden');
            document.getElementById('sdes-steps-container').innerHTML = '';
            document.getElementById('sdes-input-label').textContent = 'Plaintext (8-bit biner)';
            document.getElementById('sdes-input-counter').textContent = '0/8';
            document.getElementById('sdes-key-counter').textContent = '0/10';
            hideError('sdes-error');
        });

        toggleAllBtn.addEventListener('click', () => {
            const cards = document.querySelectorAll('#sdes-steps-container .step-card');
            const allOpen = [...cards].every(c => c.classList.contains('open'));
            cards.forEach(c => allOpen ? c.classList.remove('open') : c.classList.add('open'));
            toggleAllBtn.textContent = allOpen ? 'Buka Semua' : 'Tutup Semua';
        });
    }

    function renderResult(log) {
        const label = document.getElementById('sdes-result-label');
        const binEl = document.getElementById('sdes-result-binary');
        label.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> ${log.mode === 'encrypt' ? 'Ciphertext' : 'Plaintext'}`;
        binEl.textContent = log.result.match(/.{1,4}/g).join(' ');
        const sec = document.getElementById('sdes-result-section');
        sec.classList.remove('hidden');
        sec.classList.add('animate-in');
    }

    function renderSteps(log) {
        const stepsContainer = document.getElementById('sdes-steps-container');
        stepsContainer.innerHTML = '';

        // Key Generation
        stepsContainer.appendChild(buildKeyGenCard(log.keyGeneration));

        // Each step
        log.steps.forEach(step => {
            stepsContainer.appendChild(buildStepCard(step));
        });

        const sec = document.getElementById('sdes-steps-section');
        sec.classList.remove('hidden');
        sec.classList.add('animate-in');
        document.getElementById('sdes-toggle-all').textContent = 'Buka Semua';
    }

    function buildKeyGenCard(kg) {
        const card = createStepCard('KEY', 'badge-key', 'Key Generation (K1 & K2)');
        const body = card.querySelector('.step-body');

        let html = '<table class="ke-table"><thead><tr><th>Langkah</th><th>Detail</th><th>Hasil</th></tr></thead><tbody>';
        kg.steps.forEach(s => {
            if (s.left !== undefined) {
                html += `<tr><td class="desc-text">${s.desc}</td><td class="mono-val">L: ${s.left}</td><td class="mono-val">R: ${s.right}</td></tr>`;
            } else if (s.leftIn !== undefined) {
                html += `<tr><td class="desc-text">${s.desc}</td>
                    <td class="mono-val">L: ${s.leftIn} → ${s.leftOut}<br>R: ${s.rightIn} → ${s.rightOut}</td>
                    <td class="mono-val">${s.leftOut}${s.rightOut}</td></tr>`;
            } else if (s.input !== undefined) {
                html += `<tr><td class="desc-text">${s.desc}</td><td class="calc-text">${s.detail || ''}</td><td class="mono-val">${s.input} → ${s.output}</td></tr>`;
            } else {
                html += `<tr><td class="desc-text">${s.desc}</td><td></td><td class="mono-val">${s.value}</td></tr>`;
            }
        });
        html += '</tbody></table>';

        html += '<div class="ke-keys-summary">';
        html += `<div class="ke-key-chip"><span class="chip-label">K1</span><span class="chip-value">${sdesBitsToBin(kg.K1)}</span></div>`;
        html += `<div class="ke-key-chip"><span class="chip-label">K2</span><span class="chip-value">${sdesBitsToBin(kg.K2)}</span></div>`;
        html += '</div>';

        body.innerHTML = html;
        return card;
    }

    function buildStepCard(step) {
        if (step.operation === 'Round') {
            return buildRoundCard(step);
        }

        const badge = getSDESBadge(step.operation);
        const card = createStepCard(badge.label, badge.cls, step.name);
        const body = card.querySelector('.step-body');

        let html = '';
        if (step.operation === 'IP' || step.operation === 'IP_INV') {
            html += `<div class="info-box"><strong>${step.detail}</strong></div>`;
            html += `<div class="state-comparison">`;
            html += buildBitBlock('Input', step.input);
            html += `<div class="state-op-label"><span class="state-arrow">→</span></div>`;
            html += buildBitBlock('Output', step.output);
            html += `</div>`;
        } else if (step.operation === 'Split') {
            html += `<div class="state-comparison">`;
            html += buildBitBlock('Left (4-bit)', step.left);
            html += buildBitBlock('Right (4-bit)', step.right);
            html += `</div>`;
        } else if (step.operation === 'Swap') {
            html += `<div class="state-comparison">`;
            html += buildBitBlock('Before', step.before);
            html += `<div class="state-op-label"><span class="op-name">SWAP</span><span class="state-arrow">→</span></div>`;
            html += buildBitBlock('After', step.after);
            html += `</div>`;
        }

        body.innerHTML = html;
        return card;
    }

    function buildRoundCard(step) {
        const card = createStepCard(`R${step.round}`, 'badge-round', step.name);
        const body = card.querySelector('.step-body');
        const fl = step.feistelLog;

        let html = `<div class="info-box"><strong>Subkey:</strong> <code>${step.subkey}</code></div>`;

        // Show L and R before
        html += `<div class="state-comparison">`;
        html += buildBitBlock('L (input)', step.leftBefore);
        html += buildBitBlock('R (input)', step.rightBefore);
        html += `</div>`;

        // E/P
        html += `<h4 style="color:var(--accent-cyan);font-size:0.82rem;margin:12px 0 6px;font-weight:700;">Expansion/Permutation (E/P)</h4>`;
        html += `<div class="state-comparison">`;
        html += buildBitBlock('R (4-bit)', fl.ep.input);
        html += `<div class="state-op-label"><span class="op-name">E/P</span><span class="state-arrow">→</span></div>`;
        html += buildBitBlock('Expanded (8-bit)', fl.ep.output);
        html += `</div>`;

        // XOR with Key
        html += `<h4 style="color:var(--accent-amber);font-size:0.82rem;margin:12px 0 6px;font-weight:700;">XOR with Subkey</h4>`;
        html += `<table class="ke-table"><tbody>`;
        html += `<tr><td class="desc-text">E/P Result</td><td class="mono-val">${fl.xor.a}</td></tr>`;
        html += `<tr><td class="desc-text">Subkey</td><td class="mono-val">${fl.xor.b}</td></tr>`;
        html += `<tr><td class="desc-text">XOR Result</td><td class="mono-val">${fl.xor.result}</td></tr>`;
        html += `</tbody></table>`;

        // S-Boxes
        html += `<h4 style="color:var(--accent-emerald);font-size:0.82rem;margin:12px 0 6px;font-weight:700;">S-Box Substitution</h4>`;
        html += `<table class="ke-table"><thead><tr><th>S-Box</th><th>Input</th><th>Row</th><th>Col</th><th>Output</th></tr></thead><tbody>`;
        html += `<tr><td class="desc-text">S0</td><td class="mono-val">${fl.sbox.s0.input}</td><td class="mono-val">${fl.sbox.s0.row}</td><td class="mono-val">${fl.sbox.s0.col}</td><td class="mono-val">${fl.sbox.s0.output}</td></tr>`;
        html += `<tr><td class="desc-text">S1</td><td class="mono-val">${fl.sbox.s1.input}</td><td class="mono-val">${fl.sbox.s1.row}</td><td class="mono-val">${fl.sbox.s1.col}</td><td class="mono-val">${fl.sbox.s1.output}</td></tr>`;
        html += `</tbody></table>`;

        // P4
        html += `<h4 style="color:var(--accent-purple);font-size:0.82rem;margin:12px 0 6px;font-weight:700;">P4 Permutation</h4>`;
        html += `<div class="state-comparison">`;
        html += buildBitBlock('S-Box Output', fl.p4.input);
        html += `<div class="state-op-label"><span class="op-name">P4</span><span class="state-arrow">→</span></div>`;
        html += buildBitBlock('P4 Result', fl.p4.output);
        html += `</div>`;

        // XOR with Left
        html += `<h4 style="color:var(--accent-rose);font-size:0.82rem;margin:12px 0 6px;font-weight:700;">XOR with Left Half</h4>`;
        html += `<table class="ke-table"><tbody>`;
        html += `<tr><td class="desc-text">Left Half</td><td class="mono-val">${step.leftBefore}</td></tr>`;
        html += `<tr><td class="desc-text">f(R, K) Result</td><td class="mono-val">${step.feistelResult}</td></tr>`;
        html += `<tr><td class="desc-text">New Left = L ⊕ f</td><td class="mono-val">${step.xorWithLeft}</td></tr>`;
        html += `</tbody></table>`;

        // Output
        html += `<div class="state-comparison mt-2">`;
        html += buildBitBlock('New L', step.newLeft);
        html += buildBitBlock('R (unchanged)', step.newRight);
        html += `</div>`;

        body.innerHTML = html;
        return card;
    }

    function buildBitBlock(label, bits) {
        let html = `<div class="state-block"><div class="state-block-label">${label}</div><div class="bit-display">`;
        for (const b of bits) {
            html += `<div class="bit-cell">${b}</div>`;
        }
        html += `</div></div>`;
        return html;
    }

    function getSDESBadge(op) {
        switch(op) {
            case 'IP': return { cls: 'badge-perm', label: 'IP' };
            case 'IP_INV': return { cls: 'badge-perm', label: 'IP⁻¹' };
            case 'Split': return { cls: 'badge-initial', label: 'SPLIT' };
            case 'Swap': return { cls: 'badge-shift', label: 'SW' };
            case 'Round': return { cls: 'badge-round', label: 'ROUND' };
            default: return { cls: 'badge-initial', label: 'STEP' };
        }
    }

    return { init };
})();
