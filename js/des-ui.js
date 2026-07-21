/**
 * DES Simulator — UI Module
 * Renders form, results, and step-by-step details for DES.
 */

const DESModule = (() => {
    let container;

    function init(el) {
        container = el;
        render();
    }

    function render() {
        container.innerHTML = `
            <section class="card input-card">
                <h2 class="section-title">Input</h2>
                <form id="des-form" autocomplete="off">
                    <div class="mode-selector">
                        <label class="mode-option">
                            <input type="radio" name="des-mode" value="encrypt" checked>
                            <span class="mode-label">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                                Enkripsi
                            </span>
                        </label>
                        <label class="mode-option">
                            <input type="radio" name="des-mode" value="decrypt">
                            <span class="mode-label">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9 1"/></svg>
                                Dekripsi
                            </span>
                        </label>
                    </div>
                    <div class="format-toggle">
                        <button type="button" class="format-btn active" data-format="hex" id="des-fmt-hex">HEX</button>
                        <button type="button" class="format-btn" data-format="bin" id="des-fmt-bin">BINARY</button>
                    </div>
                    <div class="form-group">
                        <label for="des-input" id="des-input-label">Plaintext (16 hex chars)</label>
                        <input type="text" id="des-input" maxlength="64" placeholder="contoh: 0123456789ABCDEF" required>
                        <div class="input-hint">
                            <span id="des-input-hint-text">Masukkan tepat 16 karakter heksadesimal</span>
                            <span class="char-counter" id="des-input-counter">0/16</span>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="des-key" id="des-key-label">Kunci (16 hex chars)</label>
                        <input type="text" id="des-key" maxlength="64" placeholder="contoh: 133457799BBCDFF1" required>
                        <div class="input-hint">
                            <span id="des-key-hint-text">Masukkan tepat 16 karakter heksadesimal</span>
                            <span class="char-counter" id="des-key-counter">0/16</span>
                        </div>
                    </div>
                    <div class="button-group">
                        <button type="submit" class="btn btn-primary">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                            SUBMIT
                        </button>
                        <button type="button" class="btn btn-secondary" id="des-reset">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                            RESET
                        </button>
                    </div>
                </form>
            </section>
            <div class="error-message hidden" id="des-error"></div>
            <section class="card result-card hidden" id="des-result-section">
                <h2 class="section-title">Hasil</h2>
                <div class="result-display">
                    <div class="result-item">
                        <span class="result-label" id="des-result-label">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                            Ciphertext
                        </span>
                        <div class="result-values">
                            <div class="result-value">
                                <span class="value-label">Heksadesimal</span>
                                <span class="value-text mono" id="des-result-hex"></span>
                            </div>
                            <div class="result-value">
                                <span class="value-label">Biner (64-bit)</span>
                                <span class="value-text mono" id="des-result-binary" style="font-size:0.85rem;letter-spacing:0.05em;"></span>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
            <section class="card steps-card hidden" id="des-steps-section">
                <div class="steps-header">
                    <h2 class="section-title">Tampilkan Solusi Penyelesaian</h2>
                    <button type="button" class="btn btn-sm btn-outline" id="des-toggle-all">Buka Semua</button>
                </div>
                <div id="des-steps-container" class="stagger"></div>
            </section>
        `;
        bindEvents();
    }

    let currentFormat = 'hex';

    function bindEvents() {
        const form = document.getElementById('des-form');
        const inputField = document.getElementById('des-input');
        const keyField = document.getElementById('des-key');
        const resetBtn = document.getElementById('des-reset');
        const toggleAllBtn = document.getElementById('des-toggle-all');
        const fmtHex = document.getElementById('des-fmt-hex');
        const fmtBin = document.getElementById('des-fmt-bin');

        function updateFormat(fmt) {
            currentFormat = fmt;
            fmtHex.classList.toggle('active', fmt === 'hex');
            fmtBin.classList.toggle('active', fmt === 'bin');
            const mode = document.querySelector('input[name="des-mode"]:checked').value;
            const inputName = mode === 'encrypt' ? 'Plaintext' : 'Ciphertext';
            if (fmt === 'hex') {
                document.getElementById('des-input-label').textContent = `${inputName} (16 hex chars)`;
                document.getElementById('des-key-label').textContent = 'Kunci (16 hex chars)';
                inputField.maxLength = 16;
                keyField.maxLength = 16;
                inputField.placeholder = 'contoh: 0123456789ABCDEF';
                keyField.placeholder = 'contoh: 133457799BBCDFF1';
                document.getElementById('des-input-hint-text').textContent = 'Masukkan tepat 16 karakter heksadesimal';
                document.getElementById('des-key-hint-text').textContent = 'Masukkan tepat 16 karakter heksadesimal';
            } else {
                document.getElementById('des-input-label').textContent = `${inputName} (64-bit biner)`;
                document.getElementById('des-key-label').textContent = 'Kunci (64-bit biner)';
                inputField.maxLength = 64;
                keyField.maxLength = 64;
                inputField.placeholder = 'contoh: 0000000100100011...';
                keyField.placeholder = 'contoh: 0001001100110100...';
                document.getElementById('des-input-hint-text').textContent = 'Masukkan tepat 64 digit biner (0 dan 1)';
                document.getElementById('des-key-hint-text').textContent = 'Masukkan tepat 64 digit biner (0 dan 1)';
            }
            updateCounters();
        }

        function updateCounters() {
            const maxInput = currentFormat === 'hex' ? 16 : 64;
            const maxKey = currentFormat === 'hex' ? 16 : 64;
            const iLen = inputField.value.length;
            const kLen = keyField.value.length;
            const ic = document.getElementById('des-input-counter');
            const kc = document.getElementById('des-key-counter');
            ic.textContent = `${iLen}/${maxInput}`;
            ic.className = 'char-counter' + (iLen === maxInput ? ' complete' : '');
            kc.textContent = `${kLen}/${maxKey}`;
            kc.className = 'char-counter' + (kLen === maxKey ? ' complete' : '');
        }

        fmtHex.addEventListener('click', () => updateFormat('hex'));
        fmtBin.addEventListener('click', () => updateFormat('bin'));
        inputField.addEventListener('input', updateCounters);
        keyField.addEventListener('input', updateCounters);

        document.querySelectorAll('input[name="des-mode"]').forEach(r =>
            r.addEventListener('change', () => updateFormat(currentFormat)));

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            hideError('des-error');

            const inputVal = inputField.value.trim();
            const keyVal = keyField.value.trim();
            const mode = document.querySelector('input[name="des-mode"]:checked').value;

            const inputBits = desParseInput(inputVal, 64);
            if (!inputBits) {
                showError('des-error', currentFormat === 'hex'
                    ? 'Input harus berupa tepat 16 karakter heksadesimal.'
                    : 'Input harus berupa tepat 64 digit biner.');
                inputField.classList.add('error');
                return;
            }

            const keyBits = desParseInput(keyVal, 64);
            if (!keyBits) {
                showError('des-error', currentFormat === 'hex'
                    ? 'Kunci harus berupa tepat 16 karakter heksadesimal.'
                    : 'Kunci harus berupa tepat 64 digit biner.');
                keyField.classList.add('error');
                return;
            }

            inputField.classList.remove('error');
            keyField.classList.remove('error');

            const result = mode === 'encrypt'
                ? desEncrypt(inputBits, keyBits)
                : desDecrypt(inputBits, keyBits);

            renderResult(result);
            renderSteps(result);
            document.getElementById('des-result-section').scrollIntoView({ behavior: 'smooth' });
        });

        resetBtn.addEventListener('click', () => {
            form.reset();
            inputField.classList.remove('error');
            keyField.classList.remove('error');
            document.getElementById('des-result-section').classList.add('hidden');
            document.getElementById('des-steps-section').classList.add('hidden');
            document.getElementById('des-steps-container').innerHTML = '';
            hideError('des-error');
            updateFormat('hex');
        });

        toggleAllBtn.addEventListener('click', () => {
            const cards = document.querySelectorAll('#des-steps-container .step-card');
            const allOpen = [...cards].every(c => c.classList.contains('open'));
            cards.forEach(c => allOpen ? c.classList.remove('open') : c.classList.add('open'));
            toggleAllBtn.textContent = allOpen ? 'Buka Semua' : 'Tutup Semua';
        });
    }

    function renderResult(log) {
        const label = document.getElementById('des-result-label');
        const hexEl = document.getElementById('des-result-hex');
        const binEl = document.getElementById('des-result-binary');
        label.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> ${log.mode === 'encrypt' ? 'Ciphertext' : 'Plaintext'}`;
        hexEl.textContent = log.result.hex;
        binEl.textContent = log.result.binary.match(/.{1,8}/g).join(' ');
        const sec = document.getElementById('des-result-section');
        sec.classList.remove('hidden');
        sec.classList.add('animate-in');
    }

    function renderSteps(log) {
        const c = document.getElementById('des-steps-container');
        c.innerHTML = '';

        // Key Generation
        c.appendChild(buildKeyGenCard(log.keyGeneration));

        // Steps
        log.steps.forEach(step => {
            if (step.operation === 'Feistel') {
                c.appendChild(buildFeistelRoundCard(step));
            } else {
                c.appendChild(buildSimpleStepCard(step));
            }
        });

        const sec = document.getElementById('des-steps-section');
        sec.classList.remove('hidden');
        sec.classList.add('animate-in');
    }

    function buildKeyGenCard(kg) {
        const card = createStepCard('KEY', 'badge-key', 'Key Generation (16 Subkeys)');
        const body = card.querySelector('.step-body');

        let html = '<table class="ke-table"><thead><tr><th>Round</th><th>Shift</th><th>Subkey (48-bit hex)</th></tr></thead><tbody>';
        kg.roundDetails.forEach(rd => {
            html += `<tr><td class="desc-text">K${rd.round}</td><td class="mono-val">${rd.shift}</td><td class="mono-val">${rd.KiHex}</td></tr>`;
        });
        html += '</tbody></table>';
        body.innerHTML = html;
        return card;
    }

    function buildSimpleStepCard(step) {
        let badge, label;
        if (step.operation === 'IP') { badge = 'badge-perm'; label = 'IP'; }
        else if (step.operation === 'FP') { badge = 'badge-perm'; label = 'FP'; }
        else { badge = 'badge-initial'; label = 'STEP'; }

        const card = createStepCard(label, badge, step.name);
        const body = card.querySelector('.step-body');

        let html = '';
        if (step.input && step.output) {
            html += `<table class="ke-table"><tbody>`;
            html += `<tr><td class="desc-text">Input</td><td class="mono-val">${step.inputHex || ''}</td><td class="mono-val" style="font-size:0.72rem;">${step.input}</td></tr>`;
            html += `<tr><td class="desc-text">Output</td><td class="mono-val">${step.outputHex || ''}</td><td class="mono-val" style="font-size:0.72rem;">${step.output}</td></tr>`;
            html += `</tbody></table>`;
        } else if (step.value) {
            html += `<div class="info-box"><strong>Value:</strong> <code>${step.hex}</code></div>`;
        }
        body.innerHTML = html;
        return card;
    }

    function buildFeistelRoundCard(step) {
        const card = createStepCard(`R${step.round}`, 'badge-round', step.name);
        const body = card.querySelector('.step-body');

        let html = `<div class="info-box"><strong>Subkey K${step.round}:</strong> <code>${step.subkeyHex}</code></div>`;

        html += `<table class="ke-table"><thead><tr><th></th><th>Hex</th></tr></thead><tbody>`;
        html += `<tr><td class="desc-text">L input</td><td class="mono-val">${step.L_inHex}</td></tr>`;
        html += `<tr><td class="desc-text">R input</td><td class="mono-val">${step.R_inHex}</td></tr>`;

        // Feistel function details
        const fl = step.feistelLog;
        html += `<tr><td class="desc-text">E(R) Expansion</td><td class="mono-val" style="font-size:0.72rem;">${fl.expansion.output}</td></tr>`;
        html += `<tr><td class="desc-text">E(R) ⊕ K</td><td class="mono-val" style="font-size:0.72rem;">${fl.xorKey.result}</td></tr>`;

        // S-Box results summary
        const sboxResults = fl.sbox.map(s => `S${s.box}:${s.value}`).join(' ');
        html += `<tr><td class="desc-text">S-Box outputs</td><td class="mono-val" style="font-size:0.72rem;">${sboxResults}</td></tr>`;
        html += `<tr><td class="desc-text">After P</td><td class="mono-val" style="font-size:0.72rem;">${fl.permP.output}</td></tr>`;
        html += `<tr><td class="desc-text">f(R,K) result</td><td class="mono-val">${desBitsToHex(desBinToBits(step.feistelResult))}</td></tr>`;

        html += `<tr style="border-top:1px solid var(--border-subtle);"><td class="desc-text">L output</td><td class="mono-val">${step.L_outHex}</td></tr>`;
        html += `<tr><td class="desc-text">R output = L ⊕ f</td><td class="mono-val">${step.R_outHex}</td></tr>`;
        html += `</tbody></table>`;

        body.innerHTML = html;
        return card;
    }

    return { init };
})();
