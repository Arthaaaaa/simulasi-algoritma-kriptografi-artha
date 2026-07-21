/**
 * S-AES Simulator — UI Module
 * Adapted from existing S-AES app for the unified SPA.
 */

const SAESModule = (() => {
    let container;

    function init(el) {
        container = el;
        render();
    }

    function render() {
        container.innerHTML = `
            <section class="card input-card">
                <h2 class="section-title">Input</h2>
                <form id="saes-form" autocomplete="off">
                    <div class="mode-selector">
                        <label class="mode-option">
                            <input type="radio" name="saes-mode" value="encrypt" checked>
                            <span class="mode-label">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                                Enkripsi
                            </span>
                        </label>
                        <label class="mode-option">
                            <input type="radio" name="saes-mode" value="decrypt">
                            <span class="mode-label">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9 1"/></svg>
                                Dekripsi
                            </span>
                        </label>
                    </div>
                    <div class="form-group">
                        <label for="saes-input" id="saes-input-label">Plaintext (16-bit biner)</label>
                        <input type="text" id="saes-input" maxlength="16" placeholder="contoh: 1101011100101000" required>
                        <div class="input-hint">
                            <span>Masukkan tepat 16 digit biner (0 dan 1)</span>
                            <span class="char-counter" id="saes-input-counter">0/16</span>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="saes-key">Kunci (16-bit biner)</label>
                        <input type="text" id="saes-key" maxlength="16" placeholder="contoh: 0100101011110101" required>
                        <div class="input-hint">
                            <span>Masukkan tepat 16 digit biner (0 dan 1)</span>
                            <span class="char-counter" id="saes-key-counter">0/16</span>
                        </div>
                    </div>
                    <div class="button-group">
                        <button type="submit" class="btn btn-primary">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                            SUBMIT
                        </button>
                        <button type="button" class="btn btn-secondary" id="saes-reset">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                            RESET
                        </button>
                    </div>
                </form>
            </section>
            <div class="error-message hidden" id="saes-error"></div>
            <section class="card result-card hidden" id="saes-result-section">
                <h2 class="section-title">Hasil</h2>
                <div class="result-display">
                    <div class="result-item">
                        <span class="result-label" id="saes-result-label">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                            Ciphertext
                        </span>
                        <div class="result-values">
                            <div class="result-value">
                                <span class="value-label">Biner (16-bit)</span>
                                <span class="value-text mono" id="saes-result-binary"></span>
                            </div>
                            <div class="result-value">
                                <span class="value-label">Heksadesimal</span>
                                <span class="value-text mono" id="saes-result-hex">0x</span>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
            <section class="card steps-card hidden" id="saes-steps-section">
                <div class="steps-header">
                    <h2 class="section-title">Tampilkan Solusi Penyelesaian</h2>
                    <button type="button" class="btn btn-sm btn-outline" id="saes-toggle-all">Buka Semua</button>
                </div>
                <div id="saes-steps-container" class="stagger"></div>
            </section>
            <section class="card" id="saes-reference-section">
                <h2 class="section-title">Tabel Referensi</h2>
                <div class="reference-grid" id="saes-reference-grid"></div>
            </section>
        `;
        bindEvents();
        renderReferenceTables();
    }

    function bindEvents() {
        const form = document.getElementById('saes-form');
        const inputField = document.getElementById('saes-input');
        const keyField = document.getElementById('saes-key');
        const resetBtn = document.getElementById('saes-reset');
        const toggleAllBtn = document.getElementById('saes-toggle-all');

        setupCounter(inputField, document.getElementById('saes-input-counter'), 16);
        setupCounter(keyField, document.getElementById('saes-key-counter'), 16);

        document.querySelectorAll('input[name="saes-mode"]').forEach(r =>
            r.addEventListener('change', () => {
                document.getElementById('saes-input-label').textContent =
                    r.value === 'encrypt' ? 'Plaintext (16-bit biner)' : 'Ciphertext (16-bit biner)';
            }));

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            hideError('saes-error');

            const input = inputField.value.trim();
            const key = keyField.value.trim();
            const mode = document.querySelector('input[name="saes-mode"]:checked').value;

            if (!/^[01]{16}$/.test(input)) {
                showError('saes-error', 'Input harus berupa tepat 16 digit biner (0 dan 1).');
                inputField.classList.add('error');
                return;
            }
            if (!/^[01]{16}$/.test(key)) {
                showError('saes-error', 'Kunci harus berupa tepat 16 digit biner (0 dan 1).');
                keyField.classList.add('error');
                return;
            }

            inputField.classList.remove('error');
            keyField.classList.remove('error');

            const result = mode === 'encrypt' ? saesEncrypt(input, key) : saesDecrypt(input, key);
            renderResult(result);
            renderSteps(result);
            document.getElementById('saes-result-section').scrollIntoView({ behavior: 'smooth' });
        });

        resetBtn.addEventListener('click', () => {
            form.reset();
            inputField.classList.remove('error');
            keyField.classList.remove('error');
            document.getElementById('saes-result-section').classList.add('hidden');
            document.getElementById('saes-steps-section').classList.add('hidden');
            document.getElementById('saes-steps-container').innerHTML = '';
            document.getElementById('saes-input-label').textContent = 'Plaintext (16-bit biner)';
            document.getElementById('saes-input-counter').textContent = '0/16';
            document.getElementById('saes-key-counter').textContent = '0/16';
            hideError('saes-error');
        });

        toggleAllBtn.addEventListener('click', () => {
            const cards = document.querySelectorAll('#saes-steps-container .step-card');
            const allOpen = [...cards].every(c => c.classList.contains('open'));
            cards.forEach(c => allOpen ? c.classList.remove('open') : c.classList.add('open'));
            toggleAllBtn.textContent = allOpen ? 'Buka Semua' : 'Tutup Semua';
        });
    }

    function renderResult(log) {
        const label = document.getElementById('saes-result-label');
        const binEl = document.getElementById('saes-result-binary');
        const hexEl = document.getElementById('saes-result-hex');
        label.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> ${log.mode === 'encrypt' ? 'Ciphertext' : 'Plaintext'}`;
        binEl.textContent = log.result.binary.match(/.{1,4}/g).join(' ');
        hexEl.textContent = '0x' + log.result.hex;
        const sec = document.getElementById('saes-result-section');
        sec.classList.remove('hidden');
        sec.classList.add('animate-in');
    }

    function renderSteps(log) {
        const stepsContainer = document.getElementById('saes-steps-container');
        stepsContainer.innerHTML = '';

        // Key Expansion
        stepsContainer.appendChild(buildKeyExpansionCard(log.keyExpansion));

        // Each step
        log.steps.forEach(step => {
            stepsContainer.appendChild(buildStepCard(step));
        });

        const sec = document.getElementById('saes-steps-section');
        sec.classList.remove('hidden');
        sec.classList.add('animate-in');
        document.getElementById('saes-toggle-all').textContent = 'Buka Semua';
    }

    function buildKeyExpansionCard(ke) {
        const card = createStepCard('KEY', 'badge-key', 'Key Expansion');
        const body = card.querySelector('.step-body');

        let html = '<table class="ke-table"><thead><tr><th>Langkah</th><th>Nilai (Biner)</th><th>Hex</th></tr></thead><tbody>';
        ke.steps.forEach(step => {
            if (step.calculation) {
                html += `<tr><td><div class="desc-text">${step.desc}</div><div class="calc-text">${step.calculation}</div></td><td class="mono-val">${step.binary}</td><td class="mono-val">${step.hex || ''}</td></tr>`;
            } else if (step.input !== undefined && step.output !== undefined) {
                html += `<tr><td class="desc-text">${step.desc}</td><td class="mono-val">${step.input} → ${step.output}</td><td class="mono-val">${step.hexIn || ''} → ${step.hexOut || ''}</td></tr>`;
            } else {
                html += `<tr><td class="desc-text">${step.desc}</td><td class="mono-val">${step.binary}</td><td class="mono-val">${step.hex || ''}</td></tr>`;
            }
        });
        html += '</tbody></table>';

        html += '<div class="ke-keys-summary">';
        ['K0', 'K1', 'K2'].forEach((label, i) => {
            html += `<div class="ke-key-chip"><span class="chip-label">${label}</span><span class="chip-value">${word16ToBin(ke.keys[i])}<br>0x${word16ToHex(ke.keys[i])}</span></div>`;
        });
        html += '</div>';

        body.innerHTML = html;
        return card;
    }

    function buildStepCard(step) {
        const badge = getSAESBadge(step.operation);
        const card = createStepCard(badge.label, badge.cls, step.name);
        const body = card.querySelector('.step-body');

        let html = '<div class="state-comparison">';
        html += build2x2StateBlock('Sebelum', step.stateBefore);

        if (step.keyState) {
            html += `<div class="state-op-label"><span class="state-arrow">\u2295</span></div>`;
            html += build2x2StateBlock(step.operation.replace('AddRoundKey ', ''), step.keyState);
            html += `<div class="state-op-label"><span class="state-arrow">=</span></div>`;
        } else {
            html += `<div class="state-op-label"><span class="op-name">${getShortSAESOp(step.operation)}</span><span class="state-arrow">\u2192</span></div>`;
        }

        html += build2x2StateBlock('Sesudah', step.stateAfter);
        html += '</div>';

        html += `<div style="text-align:center;margin-top:8px;font-size:0.78rem;color:var(--text-muted);"><span style="font-family:var(--font-mono);letter-spacing:0.05em;">${stateToBinary(step.stateBefore)} → ${stateToBinary(step.stateAfter)}</span></div>`;

        if (step.gfDetails) {
            html += buildGFDetails(step.gfDetails, step.operation);
        }

        body.innerHTML = html;
        return card;
    }

    function build2x2StateBlock(label, state) {
        let html = `<div class="state-block"><div class="state-block-label">${label}</div><div class="state-matrix m2x2">`;
        const cellClasses = ['c0', 'c1', 'c2', 'c3'];
        const order = [[0,0],[0,1],[1,0],[1,1]];
        order.forEach(([r, c], idx) => {
            html += `<div class="state-cell ${cellClasses[idx]}"><span class="cell-hex">${nibbleToHex(state[r][c])}</span><span class="cell-bin">${nibbleToBin(state[r][c])}</span></div>`;
        });
        html += '</div></div>';
        return html;
    }

    function buildGFDetails(details, opName) {
        let html = `<div class="gf-details"><div class="gf-details-title">Detail Perhitungan ${opName} di GF(2\u2074)</div>`;
        details.forEach(colDetail => {
            html += `<div class="gf-column"><div class="gf-column-title">Kolom ${colDetail.column} (input: ${nibbleToHex(colDetail.input[0])}, ${nibbleToHex(colDetail.input[1])})</div>`;
            colDetail.calculations.forEach(calc => {
                html += `<div class="gf-calc-line"><span class="gf-highlight">${calc.label}</span> = ${calc.desc}</div>`;
                calc.terms.forEach(term => {
                    html += `<div class="gf-calc-line">&nbsp;&nbsp;${nibbleToHex(term.a)} × ${nibbleToHex(term.b)} = <span class="gf-highlight">${nibbleToHex(term.result)}</span> (${nibbleToBin(term.result)})</div>`;
                });
                html += `<div class="gf-calc-line">&nbsp;&nbsp;${nibbleToHex(calc.terms[0].result)} ⊕ ${nibbleToHex(calc.terms[1].result)} = <span class="gf-result">${nibbleToHex(calc.xorResult)}</span> (${nibbleToBin(calc.xorResult)})</div>`;
            });
            html += '</div>';
        });
        html += '</div>';
        return html;
    }

    function getSAESBadge(op) {
        if (op.includes('SubNibble') || op.includes('InvSubNibble')) return { cls: 'badge-sub', label: 'SUB' };
        if (op.includes('ShiftRow') || op.includes('InvShiftRow')) return { cls: 'badge-shift', label: 'SHIFT' };
        if (op.includes('MixColumn') || op.includes('InvMixColumn')) return { cls: 'badge-mix', label: 'MIX' };
        if (op.includes('AddRoundKey')) return { cls: 'badge-addrk', label: 'ARK' };
        return { cls: 'badge-initial', label: 'INIT' };
    }

    function getShortSAESOp(op) {
        if (op.includes('SubNibble')) return 'S-Box';
        if (op.includes('InvSubNibble')) return 'Inv S-Box';
        if (op.includes('ShiftRow')) return 'Shift';
        if (op.includes('InvShiftRow')) return 'Inv Shift';
        if (op.includes('MixColumn')) return 'Mix';
        if (op.includes('InvMixColumn')) return 'Inv Mix';
        return '';
    }

    function renderReferenceTables() {
        const grid = document.getElementById('saes-reference-grid');
        if (!grid) return;
        grid.innerHTML = '';

        // S-Box
        grid.appendChild(buildSBoxRefBlock('S-Box (SubNibble)', SBOX));
        grid.appendChild(buildSBoxRefBlock('Inverse S-Box', INV_SBOX));

        // MixColumns Matrix
        const mixBlock = document.createElement('div');
        mixBlock.className = 'ref-block';
        mixBlock.innerHTML = `
            <div class="ref-block-title">Matriks MixColumns</div>
            <table class="ref-small-table"><tr><td>1</td><td>4</td></tr><tr><td>4</td><td>1</td></tr></table>
            <div class="ref-info">Perkalian di GF(2\u2074) dengan polinomial irredusibel<br><code>x\u2074 + x + 1</code> (0x13)</div>
            <div class="ref-block-title" style="margin-top:18px;">Inverse MixColumns</div>
            <table class="ref-small-table"><tr><td>9</td><td>2</td></tr><tr><td>2</td><td>9</td></tr></table>
        `;
        grid.appendChild(mixBlock);

        // RCON
        const rconBlock = document.createElement('div');
        rconBlock.className = 'ref-block';
        rconBlock.innerHTML = `
            <div class="ref-block-title">Konstanta RCON</div>
            <table class="ke-table" style="margin:0;"><thead><tr><th>Nama</th><th>Biner</th><th>Hex</th></tr></thead><tbody>
                <tr><td class="desc-text">RCON1</td><td class="mono-val">10000000</td><td class="mono-val">0x80</td></tr>
                <tr><td class="desc-text">RCON2</td><td class="mono-val">00110000</td><td class="mono-val">0x30</td></tr>
            </tbody></table>
            <div class="ref-info" style="margin-top:18px;">
                <strong>Struktur Enkripsi S-AES:</strong><br>
                1. Key Expansion → K0, K1, K2<br>
                2. Initial AddRoundKey (K0)<br>
                3. Round 1: SubNibbles → ShiftRows → MixColumns → AddRoundKey (K1)<br>
                4. Round 2: SubNibbles → ShiftRows → AddRoundKey (K2)
            </div>
        `;
        grid.appendChild(rconBlock);
    }

    function buildSBoxRefBlock(title, table) {
        const block = document.createElement('div');
        block.className = 'ref-block';
        let headerHTML = '<thead><tr><th>In</th>';
        for (let i = 0; i < 16; i++) headerHTML += `<th>${i.toString(16).toUpperCase()}</th>`;
        headerHTML += '</tr></thead>';
        let bodyHTML = '<tbody><tr><td style="font-weight:700;color:var(--text-muted);">Out</td>';
        for (let i = 0; i < 16; i++) bodyHTML += `<td>${table[i].toString(16).toUpperCase()}</td>`;
        bodyHTML += '</tr></tbody>';
        block.innerHTML = `<div class="ref-block-title">${title}</div><table class="ref-table">${headerHTML}${bodyHTML}</table>`;
        return block;
    }

    return { init };
})();
