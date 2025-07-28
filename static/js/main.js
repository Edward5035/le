// ===== GLOBAL VARIABLES =====
let currentPage = 'dashboard';
let isLoading = false;

// ===== DOM READY =====
$(document).ready(function() {
    initializeApp();
    setupEventListeners();
    setupThemeToggle();
    setupSidebarNavigation();
    setupMobileMenu();
    
    // Set initial active nav
    setActiveNavigation();
});

// ===== APP INITIALIZATION =====
function initializeApp() {
    // Load theme preference
    const savedTheme = localStorage.getItem('theme') || 'dark';
    setTheme(savedTheme);
    
    // Initialize tooltips
    initializeTooltips();
    
    // Setup page visibility handler
    setupPageVisibility();
}

// ===== THEME MANAGEMENT =====
function setupThemeToggle() {
    $('#theme-toggle').on('click', function() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
    });
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    
    // Update theme icon
    const themeIcon = $('#theme-icon');
    if (theme === 'dark') {
        themeIcon.removeClass('fa-sun').addClass('fa-moon');
    } else {
        themeIcon.removeClass('fa-moon').addClass('fa-sun');
    }
    
    // Animate theme transition
    $('body').addClass('theme-transitioning');
    setTimeout(() => {
        $('body').removeClass('theme-transitioning');
    }, 300);
}

// ===== NAVIGATION MANAGEMENT =====
function setupSidebarNavigation() {
    $('.sidebar .nav-link').on('click', function(e) {
        e.preventDefault();
        
        if (isLoading) return;
        
        const page = $(this).data('page');
        const url = $(this).attr('href');
        
        if (page && page !== currentPage) {
            navigateToPage(page, url);
        }
    });
    
    // Handle quick action navigation
    $(document).on('click', '.quick-action-btn', function(e) {
        e.preventDefault();
        
        const page = $(this).data('page');
        const url = $(this).attr('href');
        
        if (page && page !== currentPage) {
            navigateToPage(page, url);
        }
    });
}

function navigateToPage(page, url) {
    if (isLoading) return;
    
    // Show loading state
    showLoading();
    
    // Update URL without page reload
    history.pushState({ page: page }, '', url);
    
    // Simulate AJAX navigation with a smooth transition
    setTimeout(() => {
        window.location.href = url;
    }, 500);
    
    currentPage = page;
}

function setActiveNavigation() {
    const path = window.location.pathname;
    
    // Remove active class from all nav links
    $('.sidebar .nav-link').removeClass('active');
    
    // Set active based on current path
    let activePage = 'dashboard';
    if (path.includes('/builder')) activePage = 'builder';
    else if (path.includes('/activator')) activePage = 'activator';
    else if (path.includes('/vault')) activePage = 'vault';
    else if (path.includes('/promoter')) activePage = 'promoter';
    else if (path.includes('/niches')) activePage = 'niches';
    
    // Add active class to current nav
    $(`.sidebar .nav-link[data-page="${activePage}"]`).addClass('active');
    currentPage = activePage;
}

// ===== MOBILE MENU =====
function setupMobileMenu() {
    $('#sidebar-toggle').on('click', function() {
        $('#sidebar').toggleClass('show');
        
        // Add overlay for mobile
        if ($('#sidebar').hasClass('show')) {
            $('body').append('<div class="sidebar-overlay"></div>');
            $('.sidebar-overlay').on('click', function() {
                $('#sidebar').removeClass('show');
                $(this).remove();
            });
        } else {
            $('.sidebar-overlay').remove();
        }
    });
    
    // Close sidebar when clicking nav link on mobile
    $('.sidebar .nav-link').on('click', function() {
        if ($(window).width() < 992) {
            $('#sidebar').removeClass('show');
            $('.sidebar-overlay').remove();
        }
    });
}

// ===== LOADING MANAGEMENT =====
function showLoading() {
    isLoading = true;
    $('#loading-overlay').addClass('show');
    
    // Add loading animation to buttons
    $('.btn').addClass('loading').prop('disabled', true);
}

function hideLoading() {
    isLoading = false;
    $('#loading-overlay').removeClass('show');
    
    // Remove loading animation from buttons
    $('.btn').removeClass('loading').prop('disabled', false);
}

// ===== ALERT SYSTEM =====
function showAlert(type, message, duration = 5000) {
    const alertId = 'alert-' + Date.now();
    const alertHtml = `
        <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
            <i class="fas fa-${getAlertIcon(type)} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    $('#alert-container').append(alertHtml);
    
    // Auto dismiss after duration
    setTimeout(() => {
        $(`#${alertId}`).fadeOut(300, function() {
            $(this).remove();
        });
    }, duration);
    
    // Animate in
    $(`#${alertId}`).hide().slideDown(300);
}

function getAlertIcon(type) {
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-circle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

// ===== EVENT LISTENERS =====
function setupEventListeners() {
    // Handle browser back/forward
    window.addEventListener('popstate', function(e) {
        if (e.state && e.state.page) {
            window.location.reload();
        }
    });
    
    // Global click handler for copy buttons
    $(document).on('click', '[data-copy]', function() {
        const textToCopy = $(this).data('copy');
        copyToClipboard(textToCopy);
    });
    
    // Global form submission handler
    $(document).on('submit', 'form[data-ajax="true"]', function(e) {
        e.preventDefault();
        handleAjaxForm(this);
    });
    
    // Tooltip re-initialization for dynamic content
    $(document).on('DOMNodeInserted', function() {
        initializeTooltips();
    });
    
    // Auto-resize textareas
    $(document).on('input', 'textarea[data-auto-resize]', function() {
        autoResizeTextarea(this);
    });
}

// ===== UTILITY FUNCTIONS =====
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function() {
            showAlert('success', 'Copied to clipboard!', 2000);
        }).catch(function() {
            fallbackCopyToClipboard(text);
        });
    } else {
        fallbackCopyToClipboard(text);
    }
}

function fallbackCopyToClipboard(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    textArea.style.top = "-999999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showAlert('success', 'Copied to clipboard!', 2000);
    } catch (err) {
        showAlert('danger', 'Failed to copy to clipboard');
    }
    
    document.body.removeChild(textArea);
}

function initializeTooltips() {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

function autoResizeTextarea(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = textarea.scrollHeight + 'px';
}

function setupPageVisibility() {
    // Handle page visibility change
    document.addEventListener('visibilitychange', function() {
        if (document.visibilityState === 'visible') {
            // Refresh certain elements when page becomes visible
            refreshDashboardStats();
        }
    });
}

function refreshDashboardStats() {
    if (currentPage === 'dashboard') {
        // Refresh dashboard statistics
        $.get('/api/dashboard', function(data) {
            if (data.stats) {
                updateStatsCards(data.stats);
            }
        }).fail(function() {
            console.log('Failed to refresh dashboard stats');
        });
    }
}

function updateStatsCards(stats) {
    $('.stats-number').each(function() {
        const $this = $(this);
        const statType = $this.closest('.stats-card').find('.stats-label').text().toLowerCase();
        
        let newValue;
        if (statType.includes('funnel')) newValue = stats.ai_funnels;
        else if (statType.includes('link')) newValue = stats.links_activated;
        else if (statType.includes('bonus')) newValue = stats.bonuses_delivered;
        else if (statType.includes('social')) newValue = stats.social_posts;
        else if (statType.includes('niche')) newValue = stats.niches_deployed;
        
        if (newValue !== undefined) {
            animateNumber($this, parseInt($this.text()), newValue);
        }
    });
}

function animateNumber($element, from, to) {
    $({ count: from }).animate({ count: to }, {
        duration: 1000,
        step: function() {
            $element.text(Math.floor(this.count));
        },
        complete: function() {
            $element.text(to);
        }
    });
}

// ===== AJAX FORM HANDLER =====
function handleAjaxForm(form) {
    const $form = $(form);
    const url = $form.attr('action') || window.location.pathname;
    const method = $form.attr('method') || 'POST';
    const formData = new FormData(form);
    
    showLoading();
    
    $.ajax({
        url: url,
        method: method,
        data: formData,
        processData: false,
        contentType: false,
        success: function(response) {
            hideLoading();
            if (response.success) {
                showAlert('success', response.message || 'Operation completed successfully!');
                
                // Trigger custom success event
                $form.trigger('ajax:success', [response]);
            } else {
                showAlert('danger', response.message || 'Operation failed');
            }
        },
        error: function(xhr) {
            hideLoading();
            let errorMessage = 'An error occurred';
            
            if (xhr.responseJSON && xhr.responseJSON.message) {
                errorMessage = xhr.responseJSON.message;
            } else if (xhr.status === 404) {
                errorMessage = 'Resource not found';
            } else if (xhr.status === 500) {
                errorMessage = 'Server error occurred';
            }
            
            showAlert('danger', errorMessage);
            
            // Trigger custom error event
            $form.trigger('ajax:error', [xhr]);
        }
    });
}

// ===== ANIMATION HELPERS =====
function fadeInElements() {
    $('.fade-in').each(function(index) {
        const $this = $(this);
        setTimeout(() => {
            $this.addClass('animated');
        }, index * 100);
    });
}

function slideUpElements() {
    $('.slide-up').each(function(index) {
        const $this = $(this);
        setTimeout(() => {
            $this.addClass('animated');
        }, index * 150);
    });
}

// ===== SEARCH FUNCTIONALITY =====
function setupGlobalSearch() {
    // Global search functionality (if needed)
    $('#global-search').on('input', debounce(function() {
        const query = $(this).val().trim();
        if (query.length > 2) {
            performGlobalSearch(query);
        } else {
            clearSearchResults();
        }
    }, 300));
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function performGlobalSearch(query) {
    // Implement global search logic
    console.log('Searching for:', query);
}

function clearSearchResults() {
    // Clear search results
    $('#search-results').empty();
}

// ===== KEYBOARD SHORTCUTS =====
function setupKeyboardShortcuts() {
    $(document).on('keydown', function(e) {
        // Ctrl/Cmd + K for search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            $('#global-search').focus();
        }
        
        // Escape to close modals
        if (e.key === 'Escape') {
            $('.modal.show').modal('hide');
            $('#sidebar').removeClass('show');
            $('.sidebar-overlay').remove();
        }
        
        // Ctrl/Cmd + / for shortcuts help
        if ((e.ctrlKey || e.metaKey) && e.key === '/') {
            e.preventDefault();
            showShortcutsModal();
        }
    });
}

function showShortcutsModal() {
    // Show keyboard shortcuts modal
    const shortcutsHtml = `
        <div class="modal fade" id="shortcutsModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Keyboard Shortcuts</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-6"><kbd>Ctrl</kbd> + <kbd>K</kbd></div>
                            <div class="col-6">Search</div>
                        </div>
                        <div class="row mt-2">
                            <div class="col-6"><kbd>Esc</kbd></div>
                            <div class="col-6">Close modals</div>
                        </div>
                        <div class="row mt-2">
                            <div class="col-6"><kbd>Ctrl</kbd> + <kbd>/</kbd></div>
                            <div class="col-6">Show shortcuts</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    if (!$('#shortcutsModal').length) {
        $('body').append(shortcutsHtml);
    }
    
    $('#shortcutsModal').modal('show');
}

// ===== PERFORMANCE OPTIMIZATION =====
function optimizePerformance() {
    // Lazy load images
    if ('IntersectionObserver' in window) {
        const imageObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.classList.remove('lazy');
                    imageObserver.unobserve(img);
                }
            });
        });
        
        document.querySelectorAll('img[data-src]').forEach(img => {
            imageObserver.observe(img);
        });
    }
    
    // Debounce scroll events
    let scrollTimer;
    $(window).on('scroll', function() {
        clearTimeout(scrollTimer);
        scrollTimer = setTimeout(function() {
            handleScrollEffects();
        }, 10);
    });
}

function handleScrollEffects() {
    // Handle scroll-based animations and effects
    const scrollTop = $(window).scrollTop();
    
    // Parallax effects
    $('.parallax').each(function() {
        const $this = $(this);
        const speed = $this.data('speed') || 0.5;
        const yPos = -(scrollTop * speed);
        $this.css('transform', `translateY(${yPos}px)`);
    });
    
    // Reveal animations
    $('.reveal-on-scroll').each(function() {
        const $this = $(this);
        const elementTop = $this.offset().top;
        const elementBottom = elementTop + $this.outerHeight();
        const viewportTop = scrollTop;
        const viewportBottom = viewportTop + $(window).height();
        
        if (elementBottom > viewportTop && elementTop < viewportBottom) {
            $this.addClass('revealed');
        }
    });
}

// ===== ERROR HANDLING =====
window.addEventListener('error', function(e) {
    console.error('Global error:', e.error);
    
    // Show user-friendly error message for critical errors
    if (e.error && e.error.stack && e.error.stack.includes('ChunkLoadError')) {
        showAlert('warning', 'The application has been updated. Please refresh the page.', 10000);
    }
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
});

// ===== INITIALIZE ADDITIONAL FEATURES =====
$(document).ready(function() {
    setupKeyboardShortcuts();
    optimizePerformance();
    fadeInElements();
    slideUpElements();
    
    // Initialize any additional features based on current page
    if (typeof initPageSpecificFeatures === 'function') {
        initPageSpecificFeatures();
    }
});

// ===== EXPORT FUNCTIONS FOR GLOBAL USE =====
window.SalesStormAI = {
    showAlert,
    showLoading,
    hideLoading,
    copyToClipboard,
    navigateToPage,
    setTheme,
    refreshDashboardStats
};