/**
 * CodeMind Website - Premium JavaScript
 * Inspired by: Indexsy, LocalRank, Mintlify
 */

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initInstallMethods();
    initCopyButtons();
    initSmoothScroll();
    initTerminalAnimation();
    initScrollReveal();
    initAnnouncementBar();
});

/**
 * Navigation functionality
 */
function initNavigation() {
    const nav = document.getElementById('nav');
    const navToggle = document.getElementById('navToggle');
    const navLinks = document.getElementById('navLinks');
    
    // Scroll effect - add background on scroll
    let lastScroll = 0;
    window.addEventListener('scroll', () => {
        const currentScroll = window.pageYOffset;
        
        if (currentScroll > 50) {
            nav.style.backdropFilter = 'blur(20px)';
            nav.style.background = 'rgba(9, 9, 11, 0.95)';
        } else {
            nav.style.backdropFilter = 'blur(16px)';
            nav.style.background = 'rgba(9, 9, 11, 0.8)';
        }
        
        lastScroll = currentScroll;
    });
    
    // Mobile menu toggle
    if (navToggle && navLinks) {
        navToggle.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            navToggle.classList.toggle('active');
        });
    }
}

/**
 * Announcement bar dismissal
 */
function initAnnouncementBar() {
    const bar = document.querySelector('.announcement-bar');
    if (!bar) return;
    
    // Check if dismissed
    if (localStorage.getItem('codemind_announcement_dismissed')) {
        bar.style.display = 'none';
        document.querySelector('.nav').style.top = '0';
        document.querySelector('.hero').style.paddingTop = 'calc(64px + 5rem)';
    }
}

/**
 * Installation method tabs
 */
function initInstallMethods() {
    const methods = document.querySelectorAll('.install-method');
    const commandEl = document.getElementById('installCommand');
    
    const commands = {
        pip: 'pip install codemind',
        pipx: 'pipx install codemind'
    };
    
    methods.forEach(method => {
        method.addEventListener('click', () => {
            const methodType = method.dataset.method;
            
            // Update active state
            methods.forEach(m => m.classList.remove('active'));
            method.classList.add('active');
            
            // Update command
            if (commandEl && commands[methodType]) {
                commandEl.textContent = commands[methodType];
                
                // Update copy button data
                const copyBtn = document.querySelector('.code-copy');
                if (copyBtn) {
                    copyBtn.dataset.copy = `${commands[methodType]} && codemind install`;
                }
            }
        });
    });
}

/**
 * Copy to clipboard functionality
 */
function initCopyButtons() {
    const copyButtons = document.querySelectorAll('.code-copy, [data-copy]');
    
    copyButtons.forEach(btn => {
        btn.addEventListener('click', async () => {
            const textToCopy = btn.dataset.copy || btn.getAttribute('data-copy');
            if (!textToCopy) return;
            
            try {
                await navigator.clipboard.writeText(textToCopy);
                
                // Visual feedback
                const originalHTML = btn.innerHTML;
                btn.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    Copied!
                `;
                btn.style.color = '#22c55e';
                
                setTimeout(() => {
                    btn.innerHTML = originalHTML;
                    btn.style.color = '';
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        });
    });
}

/**
 * Smooth scrolling for anchor links
 */
function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const target = document.querySelector(targetId);
            if (target) {
                const navHeight = document.querySelector('.nav').offsetHeight;
                const announcementBar = document.querySelector('.announcement-bar');
                const announcementHeight = announcementBar ? announcementBar.offsetHeight : 0;
                const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - navHeight - announcementHeight - 20;
                
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });
}

/**
 * Terminal typing animation
 */
function initTerminalAnimation() {
    const terminal = document.querySelector('.terminal-body');
    if (!terminal) return;
    
    // Intersection observer for replaying animation
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const lines = terminal.querySelectorAll('.terminal-line');
                lines.forEach((line, index) => {
                    line.style.animation = 'none';
                    line.offsetHeight; // Trigger reflow
                    line.style.animation = `fadeInLine 0.4s ease forwards`;
                    line.style.animationDelay = `${0.3 + (index * 0.6)}s`;
                });
            }
        });
    }, { threshold: 0.3 });
    
    observer.observe(terminal);
}

/**
 * Scroll reveal animations
 */
function initScrollReveal() {
    const revealElements = document.querySelectorAll('.feature-card, .step, .ide-card, .problem-content, .solution-content');
    
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('revealed');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);
    
    revealElements.forEach(el => {
        el.classList.add('reveal-on-scroll');
        observer.observe(el);
    });
    
    // Add CSS for reveal animation
    const style = document.createElement('style');
    style.textContent = `
        .reveal-on-scroll {
            opacity: 0;
            transform: translateY(20px);
            transition: opacity 0.6s ease, transform 0.6s ease;
        }
        .reveal-on-scroll.revealed {
            opacity: 1;
            transform: translateY(0);
        }
    `;
    document.head.appendChild(style);
}

/**
 * Add gradient cursor effect to hero
 */
function initCursorGradient() {
    const hero = document.querySelector('.hero');
    if (!hero) return;
    
    hero.addEventListener('mousemove', (e) => {
        const rect = hero.getBoundingClientRect();
        const x = ((e.clientX - rect.left) / rect.width) * 100;
        const y = ((e.clientY - rect.top) / rect.height) * 100;
        
        hero.style.setProperty('--mouse-x', `${x}%`);
        hero.style.setProperty('--mouse-y', `${y}%`);
    });
}

// Initialize cursor gradient on load
document.addEventListener('DOMContentLoaded', initCursorGradient);

/**
 * Stats counter animation
 */
function initStatsCounter() {
    const stats = document.querySelectorAll('.stat-value');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const stat = entry.target;
                const finalValue = stat.textContent;
                
                // Simple animation for non-numeric values
                if (finalValue === '100%') {
                    animateValue(stat, 0, 100, 1000, '%');
                } else if (!isNaN(parseInt(finalValue))) {
                    animateValue(stat, 0, parseInt(finalValue), 800);
                }
                
                observer.unobserve(stat);
            }
        });
    }, { threshold: 0.5 });
    
    stats.forEach(stat => observer.observe(stat));
}

function animateValue(element, start, end, duration, suffix = '') {
    const range = end - start;
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Easing function
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (range * easeOut));
        
        element.textContent = current + suffix;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

// Initialize stats counter
document.addEventListener('DOMContentLoaded', initStatsCounter);
