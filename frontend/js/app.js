/**
 * AirGap Sentinel - Zero-Exfiltration Local Code Defense Controller
 */

const App = {
  apiBase: (() => {
    // If running in browser on a remote/hosted domain (e.g. Vercel, Netlify, Railway, Render)
    if (typeof window !== 'undefined' && window.location) {
      const isLocalhost = window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost';
      if (!isLocalhost) {
        return window.location.origin;
      }
      if (window.location.port === '8080') {
        return localStorage.getItem('codeleak_api_url') || 'http://127.0.0.1:8001';
      }
      return window.location.origin;
    }
    return 'http://127.0.0.1:8001';
  })(),
  candidateBases: ['http://127.0.0.1:8001', 'http://127.0.0.1:8000'],
  currentUser: JSON.parse(localStorage.getItem('codeleak_user') || 'null'),
  currentAudit: null,
  auditsHistory: [],
  policiesList: [],
  activeFilter: 'ALL',
  searchQuery: '',
  searchDebounceTimer: null,

  // Preset sample code snippets for Screening Studio (Sandbox)
  samples: {
    aws_secret: [
      'diff --git a/backend/config.py b/backend/config.py',
      '--- a/backend/config.py',
      '+++ b/backend/config.py',
      '@@ -10,2 +10,4 @@',
      ' # Cloud production storage keys',
      '+AWS_ACCESS_KEY_ID = "' + 'AKIA' + 'IOSFODNN7EXAMPLE"',
      '+AWS_SECRET_ACCESS_KEY = "' + 'wJalrXUtnFEMI/K7MDENG/' + 'bPxRfiCYEXAMPLEKEY"',
      ''
    ].join('\n'),
    sql_injection: [
      '+++ b/services/auth_service.py',
      '@@ -45,3 +45,4 @@',
      ' def authenticate_user(username, password):',
      '-    return db.query(User).filter_by(username=username).first()',
      "+    query = f\"SELECT * FROM users WHERE user = '{username}' AND pass = '{password}'\"",
      '+    return cursor.execute(query)',
      ''
    ].join('\n'),
    broken_crypto: [
      '+++ b/utils/crypto_helper.py',
      '@@ -1,4 +1,6 @@',
      '+import hashlib',
      '+',
      ' def hash_user_token(raw_token):',
      '+    # Insecure legacy MD5 hashing',
      "+    return hashlib." + "md5(raw_token.encode('utf-8')).hexdigest()",
      ''
    ].join('\n'),
    path_traversal: [
      '+++ b/routes/download.py',
      '@@ -12,3 +12,4 @@',
      ' def get_report():',
      '+    file_name = request.args.get("file")',
      '+    return open(f"/app/data/reports/{file_name}", "rb").read()',
      ''
    ].join('\n'),
    clean_code: [
      'diff --git a/services/payment.py b/services/payment.py',
      '--- a/services/payment.py',
      '+++ b/services/payment.py',
      '@@ -1,4 +1,7 @@',
      '+import os',
      '+',
      ' def get_stripe_client():',
      '+    # Safely loaded from local environment secret store',
      '+    api_key = os.environ.get("STRIPE_API_KEY")',
      '+    return StripeClient(api_key=api_key)',
      ''
    ].join('\n')
  },

  init() {
    this.renderUserAuth();
    this.updateDownloadLinks();
    this.bindEvents();
    this.checkHealth();
    this.fetchStats();
    this.fetchAudits();
    this.fetchPolicies();

    // Pre-populate Sandbox editor space box if empty
    const inputArea = document.getElementById('sandbox-code-input');
    if (inputArea && !inputArea.value) {
      inputArea.value = this.samples.aws_secret;
      this.updateCharCounter();
      const firstChip = document.querySelector('.scenario-pill-btn[data-sample="aws_secret"]');
      if (firstChip) firstChip.classList.add('active');
    }

    // Auto-refresh telemetry every 15 seconds
    setInterval(() => this.checkHealth(), 15000);
  },

  bindEvents() {
    // Navigation Tabs
    document.querySelectorAll('.cine-nav-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const tab = e.currentTarget.dataset.tab;
        if (tab) {
          this.switchTab(tab);
        }
      });
    });

    // Close Modals on Overlay Click
    document.querySelectorAll('.cine-modal-overlay').forEach(overlay => {
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          this.closeModal();
          this.closeLoginModal();
          this.closeDownloadModal();
        }
      });
    });

    // Global Keydown (Escape closes modals/clear search, / focuses search)
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeModal();
        this.closeLoginModal();
        this.closeDownloadModal();
        const menu = document.getElementById('user-dropdown-menu');
        if (menu) menu.classList.remove('show');
      }
    });

    // Close user dropdown and engine hub popover on outside click
    document.addEventListener('click', (e) => {
      const menu = document.getElementById('user-dropdown-menu');
      const wrap = document.getElementById('header-auth-container');
      if (menu && menu.classList.contains('show') && (!wrap || !wrap.contains(e.target))) {
        menu.classList.remove('show');
      }

      const enginePop = document.getElementById('engine-hub-popover');
      const enginePill = document.getElementById('engine-hub-pill');
      if (enginePop && enginePop.classList.contains('show') && (!enginePill || !enginePill.contains(e.target))) {
        enginePop.classList.remove('show');
      }
    });

    // Omni-Search Bar Input with Debouncing
    const searchInput = document.getElementById('omni-search-input');
    const clearBtn = document.getElementById('search-clear-btn');

    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        const val = e.target.value.trim();
        this.searchQuery = val;
        if (clearBtn) {
          clearBtn.style.display = val ? 'grid' : 'none';
        }
        clearTimeout(this.searchDebounceTimer);
        this.searchDebounceTimer = setTimeout(() => {
          this.applyFilterAndSearch();
        }, 150);
      });

      // Keyboard shortcut (Escape to clear, / to focus)
      window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && document.activeElement === searchInput) {
          this.clearSearchFilter();
        } else if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
          e.preventDefault();
          searchInput.focus();
        }
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        this.clearSearchFilter();
      });
    }

    // Filter Chips
    document.querySelectorAll('.filter-chip').forEach(chip => {
      chip.addEventListener('click', (e) => {
        document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
        const target = e.currentTarget;
        target.classList.add('active');
        this.activeFilter = target.dataset.filter || 'ALL';
        this.applyFilterAndSearch();
      });
    });

    // Scenario Chips (Screening Studio)
    document.querySelectorAll('.scenario-pill-btn').forEach(chip => {
      chip.addEventListener('click', (e) => {
        document.querySelectorAll('.scenario-pill-btn').forEach(c => c.classList.remove('active'));
        const btn = e.currentTarget;
        btn.classList.add('active');
        const sampleKey = btn.dataset.sample;
        const inputArea = document.getElementById('sandbox-code-input');
        if (this.samples[sampleKey] && inputArea) {
          inputArea.value = this.samples[sampleKey];
          this.updateCharCounter();
        }
      });
    });

    // Sandbox Textarea Char Counter
    const inputArea = document.getElementById('sandbox-code-input');
    if (inputArea) {
      inputArea.addEventListener('input', () => this.updateCharCounter());
    }

    // Clear Sandbox Button
    const clearSandboxBtn = document.getElementById('btn-clear-sandbox');
    if (clearSandboxBtn) {
      clearSandboxBtn.addEventListener('click', () => {
        if (inputArea) {
          inputArea.value = '';
          this.updateCharCounter();
        }
        document.querySelectorAll('.scenario-pill-btn').forEach(c => c.classList.remove('active'));
      });
    }

    // Run Sandbox Audit Button
    const runBtn = document.getElementById('btn-run-audit');
    if (runBtn) {
      runBtn.addEventListener('click', () => this.runManualAudit());
    }

    // Modal Close Button
    const modalCloseBtn = document.getElementById('modal-close-btn');
    if (modalCloseBtn) {
      modalCloseBtn.addEventListener('click', () => this.closeModal());
    }

    // Close modal on click outside content
    const modalOverlay = document.getElementById('cine-audit-modal');
    if (modalOverlay) {
      modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) this.closeModal();
      });
    }

    // Policy search
    const policySearch = document.getElementById('policy-search-input');
    if (policySearch) {
      policySearch.addEventListener('input', (e) => this.filterPolicies(e.target.value));
    }
  },

  clearSearchFilter() {
    const searchInput = document.getElementById('omni-search-input');
    const clearBtn = document.getElementById('search-clear-btn');
    if (searchInput) {
      searchInput.value = '';
    }
    if (clearBtn) {
      clearBtn.style.display = 'none';
    }
    this.searchQuery = '';
    document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
    const allChip = document.querySelector('.filter-chip[data-filter="ALL"]');
    if (allChip) allChip.classList.add('active');
    this.activeFilter = 'ALL';
    this.applyFilterAndSearch();
  },

  setSearchQuery(q) {
    const searchInput = document.getElementById('omni-search-input');
    const clearBtn = document.getElementById('search-clear-btn');
    if (searchInput) {
      searchInput.value = q;
      this.searchQuery = q;
      if (clearBtn) clearBtn.style.display = 'grid';
      this.applyFilterAndSearch();
      this.switchTab('catalog');
    }
  },

  updateCharCounter() {
    const inputArea = document.getElementById('sandbox-code-input');
    const counter = document.getElementById('editor-char-counter');
    if (inputArea && counter) {
      const chars = inputArea.value.length;
      const lines = inputArea.value ? inputArea.value.split('\n').length : 0;
      counter.textContent = `${lines} lines, ${chars} chars`;
    }
  },

  switchTab(tabId) {
    document.querySelectorAll('.cine-nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));

    const btn = document.querySelector(`.cine-nav-btn[data-tab="${tabId}"]`);
    const view = document.getElementById(`view-${tabId}`);

    if (btn) btn.classList.add('active');
    if (view) view.classList.add('active');

    if (tabId === 'catalog') {
      this.applyFilterAndSearch();
    } else if (tabId === 'policies') {
      this.fetchPolicies();
    }
  },

  async apiRequest(path, options = {}) {
    try {
      const res = await fetch(`${this.apiBase}${path}`, {
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {})
        },
        ...options
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `HTTP ${res.status}: ${res.statusText}`);
      }
      return await res.json();
    } catch (err) {
      console.warn(`[AirGap Sentinel] API Error (${path}):`, err.message);
      throw err;
    }
  },

  async checkHealth() {
    const apiPill = document.getElementById('pill-api-status');
    const dbPill = document.getElementById('pill-db-status');
    const ollamaPill = document.getElementById('pill-ollama-status');

    let data = null;
    const isHosted = typeof window !== 'undefined' && window.location &&
                     window.location.hostname !== '127.0.0.1' &&
                     window.location.hostname !== 'localhost';

    const candidates = isHosted 
      ? [this.apiBase, window.location.origin, ''] 
      : [this.apiBase, ...this.candidateBases.filter(b => b !== this.apiBase)];

    for (const base of candidates) {
      try {
        const url = base ? `${base}/api/health` : '/api/health';
        const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
        if (res.ok) {
          data = await res.json();
          this.apiBase = base;
          if (!isHosted) localStorage.setItem('codeleak_api_url', base);
          break;
        }
      } catch (e) {}
    }

    const apiDot = document.getElementById('stat-api-dot');
    const apiDetail = document.getElementById('stat-api-detail');
    const dbDot = document.getElementById('stat-db-dot');
    const dbDetail = document.getElementById('stat-db-detail');
    const ollamaDot = document.getElementById('stat-ollama-dot');
    const ollamaDetail = document.getElementById('stat-ollama-detail');

    if (data) {
      const portStr = this.apiBase.split(':').pop();
      if (apiDot) apiDot.className = 'pulse-dot online';
      if (apiDetail) apiDetail.textContent = `Port ${portStr} • Connected & Healthy`;

      if (dbDot) dbDot.className = 'pulse-dot online';
      if (dbDetail) dbDetail.textContent = `${data.chroma_db?.indexed_policies || 8} Security Policies Ready`;

      const oData = data.ollama || {};
      if (oData.available) {
        if (ollamaDot) ollamaDot.className = 'pulse-dot online';
        if (ollamaDetail) ollamaDetail.textContent = `Model ${oData.target_model} Active`;
      } else {
        if (ollamaDot) ollamaDot.className = 'pulse-dot warning';
        if (ollamaDetail) ollamaDetail.textContent = `DevSecOps Heuristic Guard Active`;
      }
    } else {
      if (apiDot) apiDot.className = 'pulse-dot offline';
      if (apiDetail) apiDetail.textContent = `Offline (Run backend on port 8001)`;
      if (dbDot) dbDot.className = 'pulse-dot offline';
      if (dbDetail) dbDetail.textContent = `Disconnected`;
      if (ollamaDot) ollamaDot.className = 'pulse-dot offline';
      if (ollamaDetail) ollamaDetail.textContent = `Engine Offline`;
    }
  },

  toggleEnginePopover(e) {
    if (e) e.stopPropagation();
    const pop = document.getElementById('engine-hub-popover');
    if (pop) {
      pop.classList.toggle('show');
    }
  },

  async fetchStats() {
    try {
      const stats = await this.apiRequest('/api/stats');
      document.getElementById('metric-total-scans').textContent = stats.total_scans || 0;
      document.getElementById('metric-blocked').textContent = stats.blocked_commits || 0;
      document.getElementById('metric-secrets').textContent = stats.total_secrets_detected || 0;
      document.getElementById('metric-vulns').textContent = stats.total_vulnerabilities_detected || 0;
    } catch (err) {
      console.error('Failed to load stats', err);
    }
  },

  async fetchAudits() {
    try {
      const audits = await this.apiRequest('/api/audits?limit=50');
      this.auditsHistory = audits;
      this.renderHeroSpotlight(audits);
      this.applyFilterAndSearch();

      // If no active audit loaded into live screening room, load newest
      if (!this.currentAudit && audits.length > 0) {
        this.renderLiveScreening(audits[0]);
      }
    } catch (err) {
      console.error('Failed to load audits', err);
    }
  },

  renderHeroSpotlight(audits) {
    if (!audits || audits.length === 0) return;
    const cleanList = audits.filter(a => a.source !== 'git_hook' && a.source !== 'test');
    if (cleanList.length === 0) return;

    // Prefer the most recent critical blocked audit
    const heroAudit = cleanList.find(a => a.commit_blocked && a.risk_level === 'CRITICAL') 
                   || cleanList.find(a => a.commit_blocked) 
                   || cleanList[0];
    if (!heroAudit) return;
    this.heroAuditId = heroAudit.id;

    const titleEl = document.getElementById('hero-spotlight-title');
    const synopsisEl = document.getElementById('hero-spotlight-synopsis');
    const pillsEl = document.getElementById('hero-meta-pills');
    const watermarkEl = document.getElementById('hero-diff-watermark');

    const targetFile = Components.extractTargetFile(heroAudit);
    const primary = Components.extractPrimaryFinding(heroAudit);
    const isBlocked = Boolean(heroAudit.commit_blocked);
    const engineShort = (heroAudit.llm_engine || 'heuristic').includes('ollama') ? '🦙 OLLAMA GEMMA3:1B' : '🛡️ HEURISTIC ENGINE';

    if (titleEl) {
      if (primary && primary.label && isBlocked) {
        titleEl.textContent = `CRITICAL EXPOSURE: ${primary.label} in ${targetFile}`;
      } else if (isBlocked) {
        titleEl.textContent = `CRITICAL DEFENSE: Commit Blocked in ${targetFile}`;
      } else {
        titleEl.textContent = `VERIFIED SECURE: 10.0 Clean Release in ${targetFile}`;
      }
    }

    if (synopsisEl) {
      synopsisEl.textContent = heroAudit.summary 
        || "Zero-exfiltration heuristic & local neural scan intercepted unauthorized credential exposure in staged payload. Local git push successfully halted.";
    }

    if (pillsEl) {
      const risk = (heroAudit.risk_level || 'SAFE').toUpperCase();
      let cweBadge = 'CWE-798';
      const cweFinding = (heroAudit.findings || []).find(f => f.cwe);
      if (cweFinding) cweBadge = cweFinding.cwe;

      pillsEl.innerHTML = `
        <span class="hero-pill-badge ${risk === 'CRITICAL' ? 'critical' : 'safe'}">
          <span class="pulse-dot ${risk === 'CRITICAL' ? 'offline' : 'online'}"></span> ${risk} RISK
        </span>
        <span class="hero-pill-badge cwe">${Components.escapeHtml(cweBadge)}</span>
        <span class="hero-pill-badge ${isBlocked ? 'blocked' : 'passed'}">${isBlocked ? 'COMMIT BLOCKED' : 'PASSED AUDIT'}</span>
        <span class="hero-pill-badge engine">${engineShort}</span>
      `;
    }

    if (watermarkEl && heroAudit.raw_input) {
      const lines = heroAudit.raw_input.split('\n').slice(0, 10).join('\n');
      watermarkEl.textContent = lines;
    }
  },

  openHeroAudit() {
    if (this.heroAuditId) {
      this.openModal(this.heroAuditId);
    }
  },

  openHeroRemediation() {
    if (this.heroAuditId) {
      this.openModal(this.heroAuditId);
      setTimeout(() => {
        const chk = document.querySelector('.checklist-progress-box');
        if (chk) chk.scrollIntoView({ behavior: 'smooth' });
      }, 250);
    }
  },

  scrollCarousel(carouselId, direction) {
    const track = document.getElementById(carouselId);
    if (track) {
      const scrollAmount = Math.max(340, Math.round(track.clientWidth * 0.7));
      track.scrollBy({ left: direction * scrollAmount, behavior: 'smooth' });
    }
  },

  openPolicyForAudit(auditId, event) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    const audit = this.auditsHistory.find(a => a.id === auditId);
    this.switchTab('policies');
    if (audit && audit.findings && audit.findings.length > 0) {
      const cwe = audit.findings[0].cwe || '';
      const input = document.getElementById('policy-search-input');
      if (input && cwe) {
        input.value = cwe;
        this.filterPolicies(cwe);
      }
    }
  },

  openRemediationForAudit(auditId, event) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    this.openModal(auditId);
    setTimeout(() => {
      const chk = document.querySelector('.checklist-progress-box');
      if (chk) chk.scrollIntoView({ behavior: 'smooth' });
    }, 250);
  },

  async fetchPolicies() {
    try {
      const policies = await this.apiRequest('/api/policies');
      this.policiesList = policies;
      this.renderPoliciesGrid(policies);
    } catch (err) {
      console.error('Failed to load policies', err);
    }
  },

  applyFilterAndSearch() {
    const carouselsContainer = document.getElementById('catalog-carousels-container');
    const filteredSection = document.getElementById('catalog-filtered-section');
    const filteredGrid = document.getElementById('catalog-filtered-grid');
    const filteredTitle = document.getElementById('filtered-section-title');
    const filteredCount = document.getElementById('filtered-count-badge');
    const filteredIcon = document.getElementById('filtered-section-icon');

    const cleanList = this.auditsHistory.filter(a => a.source !== 'git_hook' && a.source !== 'test');
    const q = (this.searchQuery || '').toLowerCase();
    const filter = this.activeFilter;

    // Check if we are in categorized carousel mode (ALL and no search query)
    const isCarouselMode = (filter === 'ALL' && !q);

    if (isCarouselMode) {
      if (carouselsContainer) carouselsContainer.style.display = 'block';
      if (filteredSection) filteredSection.style.display = 'none';

      // Row 1: Blocked Commits
      const blockedAudits = cleanList.filter(a => a.commit_blocked || a.risk_level === 'CRITICAL');
      const trackBlocked = document.getElementById('carousel-blocked');
      const countBlocked = document.getElementById('badge-count-blocked');
      if (trackBlocked) {
        trackBlocked.innerHTML = blockedAudits.length > 0 
          ? blockedAudits.map(a => Components.renderMediaCard(a)).join('')
          : '<div class="empty-carousel-note">🎉 No blocked threats recorded. All staged code cleared.</div>';
      }
      if (countBlocked) countBlocked.textContent = blockedAudits.length;

      // Row 2: Live Commit Stream (Chronological)
      const trackStream = document.getElementById('carousel-stream');
      const countStream = document.getElementById('badge-count-stream');
      if (trackStream) {
        trackStream.innerHTML = cleanList.length > 0
          ? cleanList.map(a => Components.renderMediaCard(a)).join('')
          : '<div class="empty-carousel-note">Waiting for pre-commit diff or sandbox audit...</div>';
      }
      if (countStream) countStream.textContent = cleanList.length;

      // Row 3: Verified Clean Releases (Passed)
      const cleanAudits = cleanList.filter(a => !a.commit_blocked && a.risk_level === 'SAFE');
      const trackClean = document.getElementById('carousel-clean');
      const countClean = document.getElementById('badge-count-clean');
      if (trackClean) {
        trackClean.innerHTML = cleanAudits.length > 0
          ? cleanAudits.map(a => Components.renderMediaCard(a)).join('')
          : '<div class="empty-carousel-note">No verified clean audits yet. Run a clean scan in Sandbox.</div>';
      }
      if (countClean) countClean.textContent = cleanAudits.length;

    } else {
      // Filtered / Search Mode
      if (carouselsContainer) carouselsContainer.style.display = 'none';
      if (filteredSection) filteredSection.style.display = 'block';

      let list = [...cleanList];

      // Apply Filter Chips
      if (filter === 'BLOCKED') {
        list = list.filter(a => a.commit_blocked);
        if (filteredTitle) filteredTitle.textContent = 'Blocked Threats';
        if (filteredIcon) filteredIcon.textContent = '⛔';
      } else if (filter === 'PASSED') {
        list = list.filter(a => !a.commit_blocked);
        if (filteredTitle) filteredTitle.textContent = 'Verified Clean Code';
        if (filteredIcon) filteredIcon.textContent = '✔';
      } else if (filter === 'CRITICAL') {
        list = list.filter(a => a.risk_level === 'CRITICAL');
        if (filteredTitle) filteredTitle.textContent = 'Critical Hazard Incidents';
        if (filteredIcon) filteredIcon.textContent = '🚨';
      } else if (filter === 'SECRETS') {
        list = list.filter(a => a.total_secrets > 0);
        if (filteredTitle) filteredTitle.textContent = 'Leaked High-Entropy Secrets';
        if (filteredIcon) filteredIcon.textContent = '🔑';
      } else if (filter === 'SQLI') {
        list = list.filter(a => JSON.stringify(a.findings || []).includes('CWE-89'));
        if (filteredTitle) filteredTitle.textContent = 'CWE-89: SQL Injection';
        if (filteredIcon) filteredIcon.textContent = '💉';
      } else if (filter === 'CRYPTO') {
        list = list.filter(a => JSON.stringify(a.findings || []).includes('CWE-327'));
        if (filteredTitle) filteredTitle.textContent = 'CWE-327: Broken Crypto';
        if (filteredIcon) filteredIcon.textContent = '🔓';
      } else if (filter === 'TRAVERSAL') {
        list = list.filter(a => JSON.stringify(a.findings || []).includes('CWE-22'));
        if (filteredTitle) filteredTitle.textContent = 'CWE-22: Path Traversal';
        if (filteredIcon) filteredIcon.textContent = '📁';
      } else {
        if (filteredTitle) filteredTitle.textContent = `Search Query: "${q}"`;
        if (filteredIcon) filteredIcon.textContent = '🔍';
      }

      // Apply Search Query
      if (q) {
        list = list.filter(a => {
          const idMatch = (a.id || '').toLowerCase().includes(q);
          const sumMatch = (a.summary || '').toLowerCase().includes(q);
          const srcMatch = (a.source || '').toLowerCase().includes(q);
          const riskMatch = (a.risk_level || '').toLowerCase().includes(q);
          const findingsMatch = JSON.stringify(a.findings || []).toLowerCase().includes(q);
          return idMatch || sumMatch || srcMatch || riskMatch || findingsMatch;
        });
      }

      if (filteredCount) {
        filteredCount.textContent = `${list.length} Results`;
      }

      if (filteredGrid) {
        if (list.length === 0) {
          filteredGrid.innerHTML = Components.renderEmptyState(this.searchQuery, this.activeFilter);
        } else {
          filteredGrid.innerHTML = list.map(audit => Components.renderMediaCard(audit)).join('');
        }
      }
    }
  },

  async runManualAudit() {
    const inputArea = document.getElementById('sandbox-code-input');
    const runBtn = document.getElementById('btn-run-audit');
    const code = inputArea.value.trim();

    if (!code) {
      alert('Please select an attack scenario above or paste code / git diff content to screen.');
      return;
    }

    runBtn.disabled = true;
    runBtn.innerHTML = `<span>⚡</span> Screening Code...`;

    try {
      const audit = await this.apiRequest('/api/audit', {
        method: 'POST',
        body: JSON.stringify({
          diff: code,
          source: 'sandbox',
        }),
      });

      this.currentAudit = audit;
      this.renderLiveScreening(audit);
      this.fetchStats();
      this.fetchAudits();
      this.switchTab('live');
    } catch (err) {
      alert('Security Audit failed: ' + err.message);
    } finally {
      runBtn.disabled = false;
      runBtn.innerHTML = `<span>⚡</span> Run AirGap Audit`;
    }
  },

  renderLiveScreening(audit) {
    this.currentAudit = audit;
    const banner = document.getElementById('live-screening-banner');
    const isBlocked = audit.commit_blocked;

    banner.className = `live-screening-banner ${isBlocked ? 'blocked' : 'passed'}`;
    banner.innerHTML = `
      <div class="screening-left">
        <div class="screening-icon-box">${isBlocked ? '⛔' : '🛡️'}</div>
        <div>
          <div class="screening-title">
            ${isBlocked ? 'COMMIT REJECTED — CRITICAL DATA EXPOSURE' : 'ALL CHECKS CLEARED — REPOSITORY SECURE'}
          </div>
          <div class="screening-summary">
            ${Components.escapeHtml(audit.summary)}
          </div>
        </div>
      </div>
      <div class="screening-right">
        ${Components.renderRiskBadge(audit.risk_level)}
        ${Components.renderEngineBadge(audit.llm_engine)}
        <span style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">
          Audit #${(audit.id || '').slice(0, 8)} • ${Components.formatDate(audit.timestamp)}
        </span>
      </div>
    `;

    // Render Secrets
    const secretsContainer = document.getElementById('live-secrets-list');
    const secretCountPill = document.getElementById('live-secret-count');
    const secrets = (audit.findings || []).filter(f => f.type === 'secret');
    if (secretCountPill) secretCountPill.textContent = secrets.length;

    if (secrets.length === 0) {
      secretsContainer.innerHTML = `<div style="color:var(--text-muted); font-size:0.88rem; padding:16px 0;">✔ Zero hardcoded credentials or API keys detected. Clean!</div>`;
    } else {
      secretsContainer.innerHTML = secrets.map(s => Components.renderSecretCard(s)).join('');
    }

    // Render CWE Vulnerabilities
    const vulnsContainer = document.getElementById('live-vulns-list');
    const vulnCountPill = document.getElementById('live-vuln-count');
    const vulns = (audit.findings || []).filter(f => f.type === 'vulnerability');
    if (vulnCountPill) vulnCountPill.textContent = vulns.length;

    if (vulns.length === 0) {
      vulnsContainer.innerHTML = `<div style="color:var(--text-muted); font-size:0.88rem; padding:16px 0;">✔ Zero CWE vulnerability patterns detected. Clean!</div>`;
    } else {
      vulnsContainer.innerHTML = vulns.map(v => Components.renderVulnerabilityCard(v)).join('');
    }

    // Render RAG Policies
    const policiesContainer = document.getElementById('live-policies-list');
    const policies = audit.policies || [];
    if (policies.length === 0) {
      policiesContainer.innerHTML = `<div style="color:var(--text-muted); font-size:0.88rem; padding:12px 0;">No security policies triggered.</div>`;
    } else {
      policiesContainer.innerHTML = policies.map(p => Components.renderPolicyCard(p)).join('');
    }

    // Render Interactive Remediation Checklist
    const checklistContainer = document.getElementById('live-checklist-container');
    checklistContainer.innerHTML = Components.renderChecklist(
      audit.remediation_items,
      audit.id,
      'App.toggleTask'
    );
  },

  async toggleTask(auditId, taskId, isCompleted) {
    try {
      const updated = await this.apiRequest(`/api/audits/${auditId}/remediation/${taskId}`, {
        method: 'PATCH',
        body: JSON.stringify({ completed: isCompleted }),
      });

      if (this.currentAudit && this.currentAudit.id === auditId) {
        this.currentAudit.remediation_items = updated.remediation_items;
        const checklistContainer = document.getElementById('live-checklist-container');
        if (checklistContainer) {
          checklistContainer.innerHTML = Components.renderChecklist(
            updated.remediation_items,
            auditId,
            'App.toggleTask'
          );
        }
      }
    } catch (err) {
      alert('Failed to update remediation step: ' + err.message);
    }
  },

  async openModal(auditId) {
    const audit = this.auditsHistory.find(a => a.id === auditId);
    if (!audit) return;

    const modal = document.getElementById('cine-audit-modal');
    const modalBody = document.getElementById('modal-detail-body');
    const isBlocked = Boolean(audit.commit_blocked);
    const targetFile = Components.extractTargetFile(audit);
    const primary = Components.extractPrimaryFinding(audit);
    const shortId = (audit.id || '').slice(0, 8);
    const dateFormatted = Components.formatDate(audit.timestamp);

    // Format syntax diff lines
    let diffLinesHtml = '';
    if (audit.raw_input) {
      diffLinesHtml = audit.raw_input.split('\n').map(line => {
        let cls = '';
        if (line.startsWith('+') && !line.startsWith('+++')) cls = 'diff-add';
        else if (line.startsWith('-') && !line.startsWith('---')) cls = 'diff-del';
        else if (line.startsWith('@@')) cls = 'diff-chunk';
        return `<div class="diff-line ${cls}">${Components.escapeHtml(line)}</div>`;
      }).join('');
    }

    modalBody.innerHTML = `
      <!-- Netflix Title Inspector Hero Header -->
      <div class="modal-inspector-hero ${isBlocked ? 'blocked' : 'clean'}">
        <div class="modal-inspector-top">
          <div>
            <div style="font-size:0.75rem; font-family:var(--font-mono); color:var(--text-muted); letter-spacing:0.06em; margin-bottom:4px;">
              TITLE INSPECTOR // COMMIT #${shortId}
            </div>
            <h2 class="modal-inspector-title">📁 ${Components.escapeHtml(targetFile)}</h2>
            <div class="modal-inspector-meta">
              <span>${dateFormatted}</span>
              <span>•</span>
              <span>Origin: <strong style="color:var(--cine-cyan); text-transform:uppercase;">${audit.source || 'Sandbox'}</strong></span>
              <span>•</span>
              <span>Engine: ${Components.renderEngineBadge(audit.llm_engine)}</span>
            </div>
          </div>
          <div style="display:flex; flex-direction:column; align-items:flex-end; gap:8px;">
            <div class="modal-status-banner-pill ${isBlocked ? 'blocked' : 'passed'}">
              ${isBlocked ? '⛔ BLOCKED BY AIRGAP SENTINEL' : '✔ VERIFIED CLEAN RELEASE'}
            </div>
            ${Components.renderRiskBadge(audit.risk_level)}
          </div>
        </div>
      </div>

      <!-- Executive Synopsis Box -->
      <div style="background:rgba(18, 22, 31, 0.95); padding:20px 24px; border-radius:var(--radius-md); border:1px solid var(--border-glass); margin-bottom:24px;">
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
          <span style="font-size:1.1rem;">🧠</span>
          <strong style="color:var(--text-pure); font-size:0.96rem;">Executive AI Synopsis:</strong>
        </div>
        <p style="color:var(--text-secondary); font-size:0.92rem; line-height:1.6;">${Components.escapeHtml(audit.summary || 'Audit passed with 10.0 score. Zero leaks or CWE vulnerabilities detected.')}</p>
      </div>

      <!-- Actionable Remediation Checklist -->
      <div style="margin-bottom:28px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
          <h4 style="font-size:1.02rem; font-weight:800; color:var(--text-pure); display:flex; align-items:center; gap:8px;">
            <span>✅</span> Remediation Defense Checklist
          </h4>
          <span style="font-size:0.78rem; color:var(--text-muted);">${(audit.remediation_items || []).length} Actionable Items</span>
        </div>
        ${Components.renderChecklist(audit.remediation_items, audit.id, 'App.toggleTask')}
      </div>

      <!-- Audited Raw Diff / Staged Source Code with Syntax Highlighting -->
      <div>
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
          <h4 style="font-size:1.02rem; font-weight:800; color:var(--text-pure); display:flex; align-items:center; gap:8px;">
            <span>💻</span> Audited Unified Git Diff
          </h4>
          <span style="font-size:0.78rem; color:var(--text-muted); font-family:var(--font-mono);">${(audit.raw_input || '').split('\n').length} lines inspected</span>
        </div>
        <div class="cine-code-box diff-viewer" style="max-height:340px; overflow-y:auto; padding:14px 18px; font-family:var(--font-mono); font-size:0.84rem; line-height:1.55;">
          ${diffLinesHtml || `<code>${Components.escapeHtml(audit.raw_input || 'No code diff available')}</code>`}
        </div>
      </div>
    `;

    // Populate modal download report links and delete action
    const downloadGroup = document.getElementById('modal-report-download-group');
    if (downloadGroup) {
      downloadGroup.innerHTML = `
        <a href="${this.apiBase}/api/download/audit/${audit.id}?format=json" download="audit_${shortId}.json" class="btn-report-download" title="Download report as JSON">
          <span>📥</span> JSON Report
        </a>
        <a href="${this.apiBase}/api/download/audit/${audit.id}?format=markdown" download="audit_${shortId}.md" class="btn-report-download" title="Download report as Markdown">
          <span>📄</span> Markdown Report
        </a>
        <button onclick="App.deleteAudit('${audit.id}')" class="btn-report-download" style="color:#ff6666; border-color:rgba(229,9,20,0.4);" title="Delete this audit record">
          <span>🗑️</span> Delete
        </button>
      `;
    }

    modal.classList.add('open');
  },

  closeModal() {
    const modal = document.getElementById('cine-audit-modal');
    if (modal) modal.classList.remove('open');
  },

  async deleteAudit(auditId, event) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (!confirm('Are you sure you want to remove this audit record from the database?')) {
      return;
    }
    try {
      await this.apiRequest(`/api/audits/${auditId}`, { method: 'DELETE' });
      this.auditsHistory = this.auditsHistory.filter(a => a.id !== auditId);
      this.applyFilterAndSearch();
      this.fetchStats();
      this.closeModal();

      if (this.currentAudit && this.currentAudit.id === auditId) {
        if (this.auditsHistory.length > 0) {
          this.renderLiveScreening(this.auditsHistory[0]);
        }
      }
    } catch (err) {
      alert('Failed to delete audit: ' + err.message);
    }
  },

  // ---------------------------------------------------------
  // User Authentication & Email Login
  // ---------------------------------------------------------
  renderUserAuth() {
    const container = document.getElementById('header-auth-container');
    if (!container) return;

    if (this.currentUser && this.currentUser.email) {
      const initial = (this.currentUser.email || 'U').charAt(0).toUpperCase();
      const email = this.currentUser.email;
      const role = this.currentUser.role || 'Auditor';

      container.innerHTML = `
        <div class="user-profile-pill" onclick="App.toggleUserDropdown(event)" title="Signed in as: ${Components.escapeHtml(email)}">
          <div class="user-avatar-circle">${Components.escapeHtml(initial)}</div>
          <span class="user-email-text">${Components.escapeHtml(email)}</span>
          <span class="user-role-badge">${Components.escapeHtml(role)}</span>
          <span style="font-size:0.7rem; color:var(--text-muted);">▾</span>
        </div>
        <div class="user-dropdown-menu" id="user-dropdown-menu">
          <div class="user-dropdown-header">
            <div style="font-weight:800; color:var(--text-pure); font-size:0.86rem; word-break:break-all;">
              ${Components.escapeHtml(email)}
            </div>
            <div style="font-size:0.75rem; color:var(--cine-cyan); margin-top:2px;">
              ${Components.escapeHtml(role)}
            </div>
          </div>
          <div class="user-dropdown-item" onclick="App.openLoginModal()">
            <span>🔄</span> Switch Account
          </div>
          <div class="user-dropdown-item" onclick="App.openDownloadModal()">
            <span>📥</span> Download Center
          </div>
          <div class="user-dropdown-item danger" onclick="App.logout()">
            <span>🚪</span> Sign Out
          </div>
        </div>
      `;
    } else {
      container.innerHTML = `
        <button class="cine-btn-auth" id="btn-open-login" onclick="App.openLoginModal()">
          <span>👤</span> Sign In
        </button>
      `;
    }
  },

  toggleUserDropdown(e) {
    if (e) e.stopPropagation();
    const menu = document.getElementById('user-dropdown-menu');
    if (menu) {
      menu.classList.toggle('show');
    }
  },

  openLoginModal() {
    const modal = document.getElementById('cine-auth-modal');
    if (modal) {
      modal.classList.add('open');
      const emailInput = document.getElementById('auth-email-input');
      if (emailInput) {
        if (this.currentUser && this.currentUser.email) {
          emailInput.value = this.currentUser.email;
        }
        setTimeout(() => emailInput.focus(), 150);
      }
      this.setAuthStatus('', '');
    }
    const menu = document.getElementById('user-dropdown-menu');
    if (menu) menu.classList.remove('show');
  },

  closeLoginModal() {
    const modal = document.getElementById('cine-auth-modal');
    if (modal) modal.classList.remove('open');
  },

  setEmailPreset(email) {
    const emailInput = document.getElementById('auth-email-input');
    if (emailInput) {
      emailInput.value = email;
      emailInput.focus();
    }
  },

  togglePasswordVisibility() {
    const pwdInput = document.getElementById('auth-password-input');
    if (pwdInput) {
      pwdInput.type = pwdInput.type === 'password' ? 'text' : 'password';
    }
  },

  setAuthStatus(msg, type = 'error') {
    const alertBox = document.getElementById('auth-status-alert');
    if (!alertBox) return;
    if (!msg) {
      alertBox.style.display = 'none';
      alertBox.textContent = '';
      return;
    }
    alertBox.className = `auth-status-alert ${type}`;
    alertBox.textContent = msg;
    alertBox.style.display = 'block';
  },

  async handleLoginSubmit(event) {
    event.preventDefault();
    const emailInput = document.getElementById('auth-email-input');
    const pwdInput = document.getElementById('auth-password-input');
    const roleSelect = document.getElementById('auth-role-select');
    const rememberChk = document.getElementById('auth-remember-me');
    const submitBtn = document.getElementById('btn-submit-login');

    const email = (emailInput.value || '').trim();
    const password = (pwdInput.value || '').trim();
    const role = (roleSelect.value || 'SecOps Auditor');

    if (!email) {
      this.setAuthStatus('Please enter your email address.', 'error');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>⚡</span> Authenticating...`;

    try {
      const resp = await this.apiRequest('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email: email,
          password: password || null,
          role: role,
        }),
      });

      this.currentUser = resp.user;
      if (rememberChk && rememberChk.checked) {
        localStorage.setItem('codeleak_user', JSON.stringify(resp.user));
      } else {
        localStorage.removeItem('codeleak_user');
      }

      this.setAuthStatus(`Welcome, ${resp.user.email}! Clearance verified.`, 'success');
      this.renderUserAuth();

      setTimeout(() => {
        this.closeLoginModal();
      }, 700);
    } catch (err) {
      this.setAuthStatus(err.message || 'Authentication failed. Please check your credentials.', 'error');
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<span>⚡</span> Sign In with Your Email`;
    }
  },

  logout() {
    this.currentUser = null;
    localStorage.removeItem('codeleak_user');
    this.renderUserAuth();
    this.apiRequest('/api/auth/logout', { method: 'POST' }).catch(() => {});
  },

  // ---------------------------------------------------------
  // Download Experience Handlers
  // ---------------------------------------------------------
  openDownloadModal() {
    this.updateDownloadLinks();
    const modal = document.getElementById('cine-download-modal');
    if (modal) modal.classList.add('open');
    const menu = document.getElementById('user-dropdown-menu');
    if (menu) menu.classList.remove('show');
  },

  closeDownloadModal() {
    const modal = document.getElementById('cine-download-modal');
    if (modal) modal.classList.remove('open');
  },

  downloadFile(endpoint, filename) {
    const url = `${this.apiBase}${endpoint}`;
    const a = document.createElement('a');
    a.href = url;
    if (filename) a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  },

  updateDownloadLinks() {
    const zipLink = document.getElementById('link-download-project-zip');
    if (zipLink) zipLink.href = `${this.apiBase}/api/download/project-zip`;

    const csvLink = document.getElementById('link-download-history-csv');
    if (csvLink) csvLink.href = `${this.apiBase}/api/download/history-csv`;
  },

  renderPoliciesGrid(policies) {
    const container = document.getElementById('policies-grid-container');
    if (!container) return;

    if (policies.length === 0) {
      container.innerHTML = `<div style="color:var(--text-muted); padding:32px;">No vector policies found.</div>`;
      return;
    }

    container.innerHTML = policies.map(p => {
      const meta = p.metadata || {};
      const isCompany = p.id.startsWith('POL-');
      return `
        <div class="cine-section-box" style="margin-bottom:20px;">
          <div class="cine-section-header">
            <div style="display:flex; align-items:center; gap:10px;">
              <span style="font-size:0.75rem; font-weight:800; font-family:var(--font-mono); color:${isCompany ? 'var(--cine-purple)' : 'var(--cine-cyan)'}; background:rgba(255,255,255,0.06); padding:3px 10px; border-radius:6px; border:1px solid var(--border-glass);">
                ${Components.escapeHtml(p.id)}
              </span>
              <span style="font-weight:800; color:var(--text-pure); font-size:1rem;">${Components.escapeHtml(meta.title || p.id)}</span>
            </div>
            <span style="font-size:0.7rem; font-weight:800; padding:2px 8px; border-radius:9999px; background:rgba(229,9,20,0.15); color:var(--cine-red); border:1px solid rgba(229,9,20,0.3);">
              ${Components.escapeHtml(meta.severity || 'HIGH')}
            </span>
          </div>
          <div class="cine-section-body">
            <p style="font-size:0.9rem; color:var(--text-secondary); line-height:1.65;">${Components.escapeHtml(p.document)}</p>
          </div>
        </div>
      `;
    }).join('');
  },

  filterPolicies(query) {
    const q = (query || '').toLowerCase();
    const filtered = this.policiesList.filter(p => {
      const meta = p.metadata || {};
      return (
        p.id.toLowerCase().includes(q) ||
        (meta.title && meta.title.toLowerCase().includes(q)) ||
        (p.document && p.document.toLowerCase().includes(q))
      );
    });
    this.renderPoliciesGrid(filtered);
  }
};

window.Components = Components;
window.App = App;

document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
