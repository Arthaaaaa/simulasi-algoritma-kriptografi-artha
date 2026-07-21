/**
 * Crypto Simulator — Main App (SPA Router + Shared Utilities)
 */

// =====================================================
// SHARED UI UTILITIES (used by all modules)
// =====================================================

function showError(id, msg) {
    const el = document.getElementById(id);
    el.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg> ${msg}`;
    el.classList.remove('hidden');
}

function hideError(id) {
    document.getElementById(id).classList.add('hidden');
}

function setupCounter(field, counterEl, max) {
    field.addEventListener('input', () => {
        field.value = field.value.replace(/[^01]/g, '');
        const len = field.value.length;
        counterEl.textContent = `${len}/${max}`;
        counterEl.className = 'char-counter' + (len === max ? ' complete' : len > max ? ' over' : '');
    });
}

function setupHexCounter(field, counterEl, max) {
    field.addEventListener('input', () => {
        field.value = field.value.replace(/[^0-9a-fA-F]/g, '');
        const len = field.value.length;
        counterEl.textContent = `${len}/${max}`;
        counterEl.className = 'char-counter' + (len === max ? ' complete' : len > max ? ' over' : '');
    });
}

/** Create a reusable collapsible step card with header */
function createStepCard(badgeLabel, badgeCls, title) {
    const card = document.createElement('div');
    card.className = 'step-card';

    const header = document.createElement('div');
    header.className = 'step-header';
    header.innerHTML = `
        <span class="step-tag">
            <span class="step-badge ${badgeCls}">${badgeLabel}</span>
            ${title}
        </span>
        <span class="step-toggle">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>
        </span>
    `;
    header.addEventListener('click', () => card.classList.toggle('open'));
    card.appendChild(header);

    const body = document.createElement('div');
    body.className = 'step-body';
    card.appendChild(body);

    return card;
}

// =====================================================
// SPA ROUTER
// =====================================================

document.addEventListener('DOMContentLoaded', () => {
    const pages = {
        'home': document.getElementById('page-home'),
        'des': document.getElementById('page-des'),
        's-des': document.getElementById('page-s-des'),
        'aes': document.getElementById('page-aes'),
        's-aes': document.getElementById('page-s-aes')
    };

    const navLinks = document.querySelectorAll('.navbar-links a');
    const hamburger = document.getElementById('nav-hamburger');
    const navLinksContainer = document.getElementById('nav-links');
    let modulesInitialized = {};

    // Navbar scroll effect
    window.addEventListener('scroll', () => {
        document.getElementById('navbar').classList.toggle('scrolled', window.scrollY > 10);
    });

    // Hamburger menu
    hamburger.addEventListener('click', () => {
        navLinksContainer.classList.toggle('open');
    });

    // Navigation
    function navigate(page) {
        // Hide all pages
        Object.values(pages).forEach(p => {
            p.classList.remove('active');
            p.style.display = 'none';
        });

        // Show target page
        if (pages[page]) {
            pages[page].style.display = 'block';
            // Trigger reflow then add active class for animation
            void pages[page].offsetHeight;
            pages[page].classList.add('active');
        }

        // Update nav active state
        navLinks.forEach(link => {
            const target = link.getAttribute('data-nav');
            link.classList.toggle('active', target === page);
        });

        // Close mobile menu
        navLinksContainer.classList.remove('open');

        // Initialize modules on first visit
        if (page !== 'home' && !modulesInitialized[page]) {
            initModule(page);
            modulesInitialized[page] = true;
        }

        // Scroll to top
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function initModule(page) {
        switch(page) {
            case 'des':
                DESModule.init(document.getElementById('des-module'));
                break;
            case 's-des':
                SDESModule.init(document.getElementById('sdes-module'));
                break;
            case 'aes':
                AESModule.init(document.getElementById('aes-module'));
                break;
            case 's-aes':
                SAESModule.init(document.getElementById('saes-module'));
                break;
        }
    }

    // Hash-based routing
    function handleRoute() {
        const hash = window.location.hash.replace('#', '') || 'home';
        if (pages[hash]) {
            navigate(hash);
        } else {
            navigate('home');
        }
    }

    window.addEventListener('hashchange', handleRoute);

    // Handle click on navigation links
    document.querySelectorAll('[data-nav]').forEach(el => {
        el.addEventListener('click', (e) => {
            const target = el.getAttribute('data-nav');
            if (target === 'home') {
                e.preventDefault();
                window.location.hash = '';
                navigate('home');
            }
            // Other links use href="#xxx" which triggers hashchange
        });
    });

    // Handle module card clicks on landing page
    document.querySelectorAll('.module-card').forEach(card => {
        card.addEventListener('click', (e) => {
            // Let the href handle navigation
        });
    });

    // Initial route
    handleRoute();
});
