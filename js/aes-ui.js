/**
 * AES-128 Simulator — UI Module
 * Renders form, results, and step-by-step details for AES-128.
 */

const AESModule = (() => {
    let container;

    function init(el) {
        container = el;
        render();
    }

    function render() {
        container.innerHTML = `
            <section class="card input-card">
                <h2 class="section-title">Input</h2>
                <form id="aes-form" autocomplete="off">
                    <div class="mode-selector">
                        <label class="mode-option">
                            <input type="radio" name="aes-mode" value="encrypt" checked>
                            <span class="mode-label">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                                Enkripsi
                            </span>
                        </label>
                        <label class="mode-option">
                            <input type="radio" name="aes-mode" value="decrypt">
                            <span class="mode-label">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9 1"/></svg>
                                Dekripsi
                            </span>
                        </label>
                    </div>
                    <div class="form-group">
                        <label for="aes-input" id="aes-input-label">Plaintext (32 hex chars / 128-bit)</label>
                        <input type="text" id="aes-input" maxlength="32" placeholder="contoh: 00112233445566778899aabbccddeeff" required>
                        <div class="input-hint">
                            <span>Masukkan tepat 32 karakter heksadesimal (128-bit)</span>
                            <span class="char-counter" id="aes-input-counter">0/32</span>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="aes-key">Kunci (32 hex chars / 128-bit)</label>
                        <input type="text" id="aes-key" maxlength="32" placeholder="contoh: 000102030405060708090a0b0c0d0e0f" required>
                        <div class="input-hint">
                            <span>Masukkan tepat 32 karakter heksadesimal (128-bit)</span>
                            <span class="char-counter" id="aes-key-counter">0/32</span>
                        </div>
                    </div>
                    <div class="button-group">
                        <button type="submit" class="btn btn-primary">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                            SUBMIT
                        </button>
                        <button type="button" class="btn btn-secondary" id="aes-reset">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                            RESET
                        </button>
                    </div>
                </form>
            </section>
            <div class="error-message hidden" id="aes-error"></div>
            <section class="card result-card hidden" id="aes-result-section">
                <h2 class="section-title">Hasil</h2>
                <div class="result-display">
                    <div class="result-item">
                        <span class="result-label" id="aes-result-label">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                            Ciphertext
                        </span>
                        <div class="result-values">
                            <div class="result-value">
                                <span class="value-label">Heksadesimal (128-bit)</span>
                                <span class="value-text mono" id="aes-result-hex"></span>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
            <section class="card steps-card hidden" id="aes-steps-section">
                <div class="steps-header">
                    <h2 class="section-title">Tampilkan Solusi Penyelesaian</h2>
                    <button type="button" class="btn btn-sm btn-outline" id="aes-toggle-all">Buka Semua</button>
                </div>
                <div id="aes-steps-container" class="stagger"></div>
            </section>
        `;
        bindEvents();
    }

    function bindEvents() {
        const form = document.getElementById('aes-form');
        const inputField = document.getElementById('aes-input');
        const keyField = document.getElementById('aes-key');
        const resetBtn = document.getElementById('aes-reset');
        const toggleAllBtn = document.getElementById('aes-toggle-all');

        setupHexCounter(inputField, document.getElementById('aes-input-counter'), 32);
        setupHexCounter(keyField, document.getElementById('aes-key-counter'), 32);

        document.querySelectorAll('input[name="aes-mode"]').forEach(r =>
            r.addEventListener('change', () => {
                document.getElementById('aes-input-label').textContent =
                    r.value === 'encrypt' ? 'Plaintext (32 hex chars / 128-bit)' : 'Ciphertext (32 hex chars / 128-bit)';
            }));

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            hideError('aes-error');

            const inputVal = inputField.value.trim().replace(/\s+/g, '');
            const keyVal = keyField.value.trim().replace(/\s+/g, '');
            const mode = document.querySelector('input[name="aes-mode"]:checked').value;

            if (!/^[0-9a-fA-F]{32}$/.test(inputVal)) {
                showError('aes-error', 'Input harus berupa tepat 32 karakter heksadesimal.');
                inputField.classList.add('error');
                return;
            }
            if (!/^[0-9a-fA-F]{32}$/.test(keyVal)) {
                showError('aes-error', 'Kunci harus berupa tepat 32 karakter heksadesimal.');
                keyField.classList.add('error');
                return;
            }

            inputField.classList.remove('error');
            keyField.classList.remove('error');

            const result = mode === 'encrypt'
                ? aesEncrypt(inputVal, keyVal)
                : aesDecrypt(inputVal, keyVal);

            renderResult(result);
            renderSteps(result);
            document.getElementById('aes-result-section').scrollIntoView({ behavior: 'smooth' });
        });

        resetBtn.addEventListener('click', () => {
            form.reset();
            inputField.classList.remove('error');
            keyField.classList.remove('error');
            document.getElementById('aes-result-section').classList.add('hidden');
            document.getElementById('aes-steps-section').classList.add('hidden');
            document.getElementById('aes-steps-container').innerHTML = '';
            document.getElementById('aes-input-label').textContent = 'Plaintext (32 hex chars / 128-bit)';
            hideError('aes-error');
        });

        toggleAllBtn.addEventListener('click', () => {
            const cards = document.querySelectorAll('#aes-steps-container .step-card');
            const allOpen = [...cards].every(c => c.classList.contains('open'));
            cards.forEach(c => allOpen ? c.classList.remove('open') : c.classList.add('open'));
            toggleAllBtn.textContent = allOpen ? 'Buka Semua' : 'Tutup Semua';
        });
    }

    function renderResult(log) {
        const label = document.getElementById('aes-result-label');
        const hexEl = document.getElementById('aes-result-hex');
        label.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> ${log.mode === 'encrypt' ? 'Ciphertext' : 'Plaintext'}`;
        hexEl.textContent = log.result.hex;
        const sec = document.getElementById('aes-result-section');
        sec.classList.remove('hidden');
        sec.classList.add('animate-in');
    }

    function renderSteps(log) {
        const c = document.getElementById('aes-steps-container');
        c.innerHTML = '';

        // Key Expansion card
        c.appendChild(buildKeyExpansionCard(log.keyExpansion));

        // Steps: each round object has substeps
        log.steps.forEach(step => {
            if (step.substeps) {
                // Round card containing substeps
                const round = step.round;
                step.substeps.forEach(sub => {
                    c.appendChild(buildSubstepCard(sub));
                });
            } else {
                // Single step (initial AddRoundKey)
                c.appendChild(buildSubstepCard(step));
            }
        });

        const sec = document.getElementById('aes-steps-section');
        sec.classList.remove('hidden');
        sec.classList.add('animate-in');
    }

    function buildKeyExpansionCard(ke) {
        const card = createStepCard('KEY', 'badge-key', 'Key Expansion (11 Round Keys)');
        const body = card.querySelector('.step-body');

        let html = '';

        // Show round key generation details
        ke.steps.forEach(step => {
            if (step.words) {
                // Initial words
                html += '<div class="info-box"><strong>Initial Key Words:</strong><br>';
                step.words.forEach(w => {
                    html += `<code>${w.name}: ${w.value}</code>&nbsp;&nbsp;`;
                });
                html += '</div>';
            } else if (step.rotWord) {
                const rnd = Math.floor(step.wordIndex / 4);
                html += `<div style="margin:10px 0;padding:10px;background:rgba(255,255,255,.02);border-radius:8px;border:1px solid var(--border-subtle);">`;
                html += `<div style="font-size:0.78rem;font-weight:700;color:#c4b5fd;margin-bottom:6px;">Round ${rnd} Key Schedule (w[${step.wordIndex}])</div>`;
                html += `<table class="ke-table" style="margin:0;"><tbody>`;
                html += `<tr><td class="desc-text">RotWord</td><td class="mono-val">${step.rotWord.input} → ${step.rotWord.output}</td></tr>`;
                html += `<tr><td class="desc-text">SubWord</td><td class="mono-val">${step.subWord.input} → ${step.subWord.output}</td></tr>`;
                html += `<tr><td class="desc-text">⊕ Rcon</td><td class="mono-val">${step.rcon.value} → ${step.rcon.result}</td></tr>`;
                html += `<tr><td class="desc-text">w[${step.wordIndex-4}] ⊕ temp</td><td class="mono-val">${step.xor.wi4} ⊕ ${step.xor.temp} = ${step.xor.result}</td></tr>`;
                html += `</tbody></table></div>`;
            }
        });

        // Round keys summary
        html += '<div class="ke-keys-summary" style="flex-wrap:wrap;">';
        ke.roundKeys.forEach((rk, i) => {
            const hex = aesStateToHex(rk);
            html += `<div class="ke-key-chip" style="min-width:auto;"><span class="chip-label">RK${i}</span><span class="chip-value" style="font-size:0.72rem;">${hex}</span></div>`;
        });
        html += '</div>';

        body.innerHTML = html;
        return card;
    }

    function buildSubstepCard(step) {
        const badge = getAESBadge(step.operation);
        const card = createStepCard(badge.label, badge.cls, step.name);
        const body = card.querySelector('.step-body');

        let html = '<div class="state-comparison">';

        // State Before
        html += build4x4StateBlock('Before', step.stateBefore);

        if (step.roundKey) {
            // AddRoundKey: show ⊕ key
            html += `<div class="state-op-label"><span class="state-arrow">\u2295</span></div>`;
            html += build4x4StateBlock('Round Key', step.roundKey);
            html += `<div class="state-op-label"><span class="state-arrow">=</span></div>`;
        } else {
            html += `<div class="state-op-label"><span class="op-name">${badge.label}</span><span class="state-arrow">\u2192</span></div>`;
        }

        html += build4x4StateBlock('After', step.stateAfter);
        html += '</div>';

        body.innerHTML = html;
        return card;
    }

    function build4x4StateBlock(label, stateDisplay) {
        let html = `<div class="state-block"><div class="state-block-label">${label}</div>`;
        html += `<div class="state-matrix m4x4">`;
        for (let r = 0; r < 4; r++) {
            for (let c = 0; c < 4; c++) {
                const cls = `c${c % 4}`;
                html += `<div class="state-cell ${cls}"><span class="cell-hex">${stateDisplay[r][c]}</span></div>`;
            }
        }
        html += `</div></div>`;
        return html;
    }

    function getAESBadge(op) {
        if (op.includes('SubBytes') || op.includes('InvSubBytes')) return { cls: 'badge-sub', label: 'SUB' };
        if (op.includes('ShiftRows') || op.includes('InvShiftRows')) return { cls: 'badge-shift', label: 'SHIFT' };
        if (op.includes('MixColumns') || op.includes('InvMixColumns')) return { cls: 'badge-mix', label: 'MIX' };
        if (op.includes('AddRoundKey')) return { cls: 'badge-addrk', label: 'ARK' };
        return { cls: 'badge-initial', label: 'STEP' };
    }

    return { init };
})();
