/**
 * CodeMind Website - Main JavaScript
 */

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initInstallTabs();
    initCopyButtons();
    initSmoothScroll();
    initTerminalAnimation();
});

/**
 * Navigation functionality
 */
function initNavigation() {
    const nav = document.getElementById('nav');
    const navToggle = document.getElementById('navToggle');
    const navLinks = document.querySelector('.nav-links');
    
    // Scroll effect
    let lastScroll = 0;
    window.addEventListener('scroll', () => {
        const currentScroll = window.pageYOffset;
        
        if (currentScroll > 100) {
            nav.style.background = 'rgba(10, 10, 15, 0.95)';
        } else {
            nav.style.background = 'rgba(10, 10, 15, 0.8)';
        }
        
        lastScroll = currentScroll;
    });
    
    // Mobile menu toggle
    if (navToggle) {
        navToggle.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            navToggle.classList.toggle('active');
        });
    }
}

/**
 * Installation tabs
 */
function initInstallTabs() {
    const tabs = document.querySelectorAll('.install-tab');
    const panes = document.querySelectorAll('.install-pane');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetId = tab.dataset.tab;
            
            // Update tabs
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            // Update panes
            panes.forEach(pane => {
                pane.classList.remove('active');
                if (pane.id === targetId) {
                    pane.classList.add('active');
                }
            });
        });
    });
}

/**
 * Copy to clipboard functionality
 */
function initCopyButtons() {
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    copyButtons.forEach(btn => {
        btn.addEventListener('click', async () => {
            const textToCopy = btn.dataset.copy;
            
            try {
                await navigator.clipboard.writeText(textToCopy);
                
                // Visual feedback
                btn.classList.add('copied');
                btn.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                `;
                
                setTimeout(() => {
                    btn.classList.remove('copied');
                    btn.innerHTML = `
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                            <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path>
                        </svg>
                    `;
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
            const target = document.querySelector(this.getAttribute('href'));
            
            if (target) {
                const navHeight = document.querySelector('.nav').offsetHeight;
                const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - navHeight;
                
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
    // Animation is handled by CSS, but we could add more complex logic here
    const terminal = document.querySelector('.hero-terminal');
    
    if (terminal) {
        // Add intersection observer for replay on scroll
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    // Reset and replay animation
                    const lines = terminal.querySelectorAll('.terminal-line');
                    lines.forEach(line => {
                        line.style.animation = 'none';
                        line.offsetHeight; // Trigger reflow
                        line.style.animation = null;
                    });
                }
            });
        }, { threshold: 0.5 });
        
        observer.observe(terminal);
    }
}

/**
 * Add scroll-based reveal animations
 */
function initScrollReveal() {
    const elements = document.querySelectorAll('.feature-card, .step, .ide-card');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, { threshold: 0.1 });
    
    elements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
        observer.observe(el);
    });
}

// Initialize scroll reveal after DOM is ready
document.addEventListener('DOMContentLoaded', initScrollReveal);
