/**
 * AirGap Sentinel - Zero-Exfiltration Local Code Defense UI Components
 */

const Components = {
  /**
   * Safely escapes HTML special characters.
   */
  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },

  /**
   * Formats ISO timestamp to local readable string or relative date.
   */
  formatDate(isoStr) {
    if (!isoStr) return '2026';
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return '2026';
    }
  },

  /**
   * Generates a poster background gradient based on risk and findings.
   */
  getPosterArt(audit) {
    const isBlocked = audit.commit_blocked;
    const risk = (audit.risk_level || 'SAFE').toUpperCase();

    if (isBlocked || risk === 'CRITICAL') {
      return {
        bg: 'linear-gradient(135deg, rgba(229, 9, 20, 0.45) 0%, rgba(14, 16, 21, 0.95) 85%)',
        icon: '🚨',
        tag: 'CRITICAL HAZARD',
        rating: '★ 9.9 EXTREME',
      };
    } else if (risk === 'HIGH') {
      return {
        bg: 'linear-gradient(135deg, rgba(245, 197, 24, 0.4) 0%, rgba(14, 16, 21, 0.95) 85%)',
        icon: '⚠️',
        tag: 'HIGH RISK',
        rating: '★ 8.5 WARNING',
      };
    } else {
      return {
        bg: 'linear-gradient(135deg, rgba(16, 185, 129, 0.35) 0%, rgba(14, 16, 21, 0.95) 85%)',
        icon: '🛡️',
        tag: 'VERIFIED SECURE',
        rating: '★ 10.0 CLEAN',
      };
    }
  },

  /**
   * Extracts the primary audited file name from audit findings or git diff.
   */
  extractTargetFile(audit) {
    if (audit.findings && audit.findings.length > 0 && audit.findings[0].file) {
      return audit.findings[0].file;
    }
    if (audit.raw_input) {
      const match = audit.raw_input.match(/\+\+\+ b\/([^\s\n]+)/) || audit.raw_input.match(/diff --git a\/[^\s]+ b\/([^\s\n]+)/);
      if (match && match[1]) return match[1];
    }
    return 'staged_diff.py';
  },

  /**
   * Extracts key finding highlight for the information space box.
   */
  extractPrimaryFinding(audit) {
    if (!audit.findings || audit.findings.length === 0) {
      return {
        icon: '🛡️',
        label: 'Verified Secure Diff',
        sub: 'Clean commit diff • 0 secrets • 0 CWE flaws',
        type: 'safe',
      };
    }
    const secret = audit.findings.find(f => f.type === 'secret');
    if (secret) {
      return {
        icon: '🔑',
        label: secret.title || 'High-Entropy Secret',
        sub: `Exposed: ${secret.masked_value || '***'} (line ${secret.line || 1})`,
        type: 'danger',
      };
    }
    const vuln = audit.findings[0];
    return {
      icon: '⚠️',
      label: `${vuln.cwe || 'CWE'}: ${vuln.title}`,
      sub: `${vuln.description ? vuln.description.slice(0, 52) + '...' : 'Violation at line ' + (vuln.line || 1)}`,
      type: 'warning',
    };
  },

  /**
   * Renders a Cinejoy Media Poster Card for the Catalog Grid.
   */
  renderMediaCard(audit) {
    const art = this.getPosterArt(audit);
    const isBlocked = Boolean(audit.commit_blocked);
    const secrets = audit.total_secrets || 0;
    const vulns = audit.total_vulnerabilities || 0;
    const dateFormatted = this.formatDate(audit.timestamp);
    const sourceLabel = (audit.source || 'sandbox').replace(/git_hook|git/gi, 'SECURITY').toUpperCase();
    const shortId = (audit.id || '').slice(0, 7);
    const targetFile = this.extractTargetFile(audit);
    const primary = this.extractPrimaryFinding(audit);
    const checklistTotal = (audit.remediation_items || []).length;
    const engineShort = (audit.llm_engine || 'heuristic')
      .replace('ollama:', '🦙 ')
      .replace('heuristic-fallback', '🛡️ Heuristic');

    // Context-rich badge (PRE-COMMIT HOOK, LOCAL RUNNER, OLLAMA GEMMA:1B)
    let contextBadge = 'LOCAL RUNNER';
    if ((audit.source || '').toLowerCase().includes('git')) {
      contextBadge = 'PRE-COMMIT HOOK';
    } else if ((audit.llm_engine || '').toLowerCase().includes('ollama')) {
      contextBadge = 'OLLAMA GEMMA:1B';
    } else if ((audit.llm_engine || '').toLowerCase().includes('heuristic')) {
      contextBadge = 'HEURISTIC SHIELD';
    }

    // Extract tags from findings
    const tags = [];
    if (secrets > 0) tags.push('LEAKED SECRET');
    if (vulns > 0) tags.push('CWE FLAW');
    (audit.findings || []).slice(0, 2).forEach(f => {
      if (f.cwe && !tags.includes(f.cwe)) tags.push(f.cwe);
    });
    if (tags.length === 0) tags.push('CLEAN REPO');

    const tagsHtml = tags.map(t => {
      const isCrit = t.includes('LEAKED') || t.includes('CRITICAL');
      return `<span class="genre-tag-pill ${isCrit ? 'critical' : ''}">${this.escapeHtml(t)}</span>`;
    }).join('');

    return `
      <div class="cine-media-card netflix-tile ${isBlocked ? 'is-blocked' : 'is-passed'}" onclick="App.openModal('${audit.id}')">
        <!-- 16:9 Thumbnail Poster Space Box -->
        <div class="poster-thumb-container">
          <div class="poster-art-bg" style="background: ${art.bg};">
            <div class="poster-icon-glow">
              ${art.icon}
            </div>
            <div class="poster-code-meta">
              <span class="poster-diff-tag">AUDIT // ${shortId}</span>
              <span class="poster-file-tag">📁 ${this.escapeHtml(targetFile)}</span>
            </div>
          </div>

          <!-- Top Poster Badges -->
          <div class="poster-top-badges">
            <span class="poster-badge-quality">${contextBadge}</span>
            <span class="poster-badge-status ${isBlocked ? 'blocked' : 'passed'}">
              ${isBlocked ? '⛔ BLOCKED' : '✔ PASSED'}
            </span>
          </div>

          <!-- Netflix Hover Quick Actions Overlay -->
          <div class="netflix-card-hover-actions">
            <button class="card-quick-action-btn primary" onclick="App.openModal('${audit.id}', event)" title="Inspect Code Diff">
              <span>▶</span>
            </button>
            <button class="card-quick-action-btn" onclick="App.openPolicyForAudit('${audit.id}', event)" title="View Vector Policy">
              <span>📜</span>
            </button>
            <button class="card-quick-action-btn" onclick="App.openRemediationForAudit('${audit.id}', event)" title="Remediation Plan">
              <span>🛠️</span>
            </button>
            <button class="card-quick-action-btn danger" onclick="App.deleteAudit('${audit.id}', event)" title="Delete Audit Record">
              <span>🗑️</span>
            </button>
          </div>
        </div>

        <!-- Poster Card Info Body -->
        <div class="poster-card-body">
          <div class="card-release-meta">
            <span class="meta-year">${art.rating}</span>
            <span>•</span>
            <span>${dateFormatted}</span>
          </div>

          <div class="card-title-text" title="${this.escapeHtml(primary.label)}">
            ${shortId ? `#${shortId} — ` : ''}${this.escapeHtml(primary.label)}
          </div>

          <!-- Information Space Box (Rich Security Metadata) -->
          <div class="card-info-space-box">
            <div class="info-space-row">
              <span class="info-space-file" title="${this.escapeHtml(targetFile)}">
                <span>📁</span> ${this.escapeHtml(targetFile)}
              </span>
              <span class="info-space-engine">${this.escapeHtml(engineShort)}</span>
            </div>

            <div class="info-space-finding">
              <span class="finding-dot ${primary.type}"></span>
              <span class="finding-text">${this.escapeHtml(primary.sub)}</span>
            </div>

            <p class="card-synopsis-text" title="${this.escapeHtml(audit.summary || '')}">
              ${this.escapeHtml(audit.summary || 'Staged diff code inspection results and compliance remediation checklist.')}
            </p>
          </div>

          <!-- Tags Row -->
          <div class="card-tags-row">
            ${tagsHtml}
          </div>

          <!-- Card Bottom Meta -->
          <div class="card-bottom-footer">
            <div style="display:flex; align-items:center; gap:8px;">
              <span class="footer-stat ${secrets > 0 ? 'danger' : ''}">🔑 ${secrets} secrets</span>
              <span class="footer-stat ${vulns > 0 ? 'warning' : ''}">⚠️ ${vulns} vulns</span>
              <span class="footer-stat">✅ ${checklistTotal} tasks</span>
            </div>
            <div style="display:flex; align-items:center; gap:8px;">
              <button class="card-delete-btn" onclick="App.deleteAudit('${audit.id}', event)" title="Remove this audit record">
                🗑️
              </button>
              <span class="inspect-action-link">INSPECT ↗</span>
            </div>
          </div>
        </div>
      </div>
    `;
  },

  /**
   * Renders Shimmering Skeleton Loading Cards.
   */
  renderSkeletonGrid(count = 8) {
    let html = '';
    for (let i = 0; i < count; i++) {
      html += `
        <div class="cine-media-card" style="pointer-events:none;">
          <div class="skeleton-card"></div>
          <div class="poster-card-body" style="gap:10px; padding:18px;">
            <div style="height:14px; width:45%; background:rgba(255,255,255,0.08); border-radius:4px;"></div>
            <div style="height:20px; width:85%; background:rgba(255,255,255,0.08); border-radius:4px;"></div>
            <div style="height:14px; width:100%; background:rgba(255,255,255,0.05); border-radius:4px;"></div>
            <div style="height:14px; width:70%; background:rgba(255,255,255,0.05); border-radius:4px;"></div>
          </div>
        </div>
      `;
    }
    return html;
  },

  /**
   * Renders Cinematic Empty State when search returns 0 results.
   */
  renderEmptyState(query = '', filter = 'ALL') {
    return `
      <div class="cine-empty-state" style="grid-column: 1 / -1;">
        <div class="cine-empty-icon">🍿</div>
        <div class="cine-empty-title">No matching security records found</div>
        <div class="cine-empty-desc">
          ${query ? `No audits match your search query <strong>"${this.escapeHtml(query)}"</strong>.` : 'No security audit logs found under the active filter.'}
          <br>Try searching for "AWS", "SQL Injection", "Stripe", or clear the search filter.
        </div>
        <button class="btn-cine-ghost" style="margin-top:16px;" onclick="App.clearSearchFilter()">
          Clear Filter &amp; Show All
        </button>
      </div>
    `;
  },

  /**
   * Renders status badges.
   */
  renderRiskBadge(risk) {
    const level = (risk || 'SAFE').toUpperCase();
    const isCrit = level === 'CRITICAL';
    const isHigh = level === 'HIGH';
    const isSafe = level === 'SAFE';

    let color = 'var(--cine-emerald)';
    let bg = 'rgba(16, 185, 129, 0.15)';
    let border = 'rgba(16, 185, 129, 0.4)';

    if (isCrit) {
      color = 'var(--cine-red)';
      bg = 'rgba(229, 9, 20, 0.18)';
      border = 'rgba(229, 9, 20, 0.5)';
    } else if (isHigh) {
      color = 'var(--cine-amber)';
      bg = 'rgba(245, 197, 24, 0.18)';
      border = 'rgba(245, 197, 24, 0.5)';
    }

    return `
      <span style="display:inline-flex; align-items:center; gap:6px; font-size:0.75rem; font-weight:800; font-family:var(--font-mono); padding:4px 12px; border-radius:9999px; background:${bg}; color:${color}; border:1px solid ${border}; letter-spacing:0.04em;">
        <span class="pulse-dot ${isSafe ? 'online' : isCrit ? 'offline' : 'warning'}"></span>
        ${level}
      </span>
    `;
  },

  renderBlockedBadge(isBlocked) {
    if (isBlocked) {
      return `<span style="display:inline-flex; align-items:center; gap:4px; font-size:0.75rem; font-weight:800; padding:4px 12px; border-radius:9999px; background:rgba(229,9,20,0.2); color:#ff4d4d; border:1px solid rgba(229,9,20,0.5); box-shadow:0 0 10px rgba(229,9,20,0.25);">⛔ BLOCKED</span>`;
    }
    return `<span style="display:inline-flex; align-items:center; gap:4px; font-size:0.75rem; font-weight:800; padding:4px 12px; border-radius:9999px; background:rgba(16,185,129,0.2); color:#34d399; border:1px solid rgba(16,185,129,0.5); box-shadow:0 0 10px rgba(16,185,129,0.25);">✔ PASSED</span>`;
  },

  renderEngineBadge(engine) {
    const text = engine || 'heuristic-fallback';
    const isOllama = text.startsWith('ollama:');
    const label = isOllama ? `🦙 ${text.replace('ollama:', '')}` : `🛡️ DevSecOps Heuristic`;
    return `
      <span style="font-size:0.72rem; font-weight:700; font-family:var(--font-mono); padding:4px 10px; border-radius:var(--radius-sm); background:rgba(255,255,255,0.06); color:var(--text-secondary); border:1px solid var(--border-glass);">
        ${this.escapeHtml(label)}
      </span>
    `;
  },

  /**
   * Renders High-Entropy Secret Item for Live Screening Center.
   */
  renderSecretCard(secret) {
    const entropy = parseFloat(secret.entropy || 0);
    const meterPct = Math.min(100, Math.round((entropy / 5.5) * 100));

    return `
      <div class="cine-finding-item">
        <div class="finding-top-bar">
          <div style="display:flex; align-items:center; gap:10px; font-weight:800; font-size:1.02rem; color:var(--text-pure);">
            <span style="color:var(--cine-red); font-size:1.3rem;">🔑</span>
            <span>${this.escapeHtml(secret.title)}</span>
            <span style="font-size:0.68rem; background:rgba(229,9,20,0.2); color:var(--cine-red); padding:2px 8px; border-radius:9999px; font-weight:800; border:1px solid rgba(229,9,20,0.4);">
              ${this.escapeHtml(secret.severity)}
            </span>
          </div>
          <span style="font-family:var(--font-mono); font-size:0.78rem; color:var(--cine-amber); background:rgba(245,197,24,0.1); padding:3px 10px; border-radius:6px; border:1px solid rgba(245,197,24,0.2);">
            ${this.escapeHtml(secret.file)}:${secret.line}
          </span>
        </div>

        <div class="secret-masked-banner">
          <div>
            <span style="color:var(--cine-red); font-weight:800; margin-right:8px; font-size:0.8rem; letter-spacing:0.05em;">MASKED EXPOSURE:</span>
            <span style="color:#fca5a5; font-weight:700;">${this.escapeHtml(secret.masked_value)}</span>
          </div>
          <button class="btn-cine-ghost" style="padding:4px 12px; font-size:0.75rem;" onclick="Components.copyToClipboard('${this.escapeHtml(secret.masked_value)}')">
            📋 Copy Masked
          </button>
        </div>

        <div class="entropy-gauge-wrap">
          <span>Shannon Entropy: <strong style="color:#fff;">${entropy.toFixed(2)}</strong></span>
          <div class="entropy-track">
            <div class="entropy-fill" style="width: ${meterPct}%;"></div>
          </div>
          <span style="font-family:var(--font-mono); font-weight:700;">${meterPct}% Randomness</span>
        </div>

        <div class="cine-code-box">
          <code>${this.escapeHtml(secret.snippet || '')}</code>
        </div>

        <div style="font-size:0.82rem; color:var(--text-secondary); margin-top:10px; display:flex; align-items:flex-start; gap:8px;">
          <strong style="color:var(--cine-amber); flex-shrink:0;">💡 Remediation:</strong>
          <span>${this.escapeHtml(secret.remediation || 'Store credentials strictly in .env files excluded via .gitignore.')}</span>
        </div>
      </div>
    `;
  },

  /**
   * Renders CWE Vulnerability Item for Live Screening Center.
   */
  renderVulnerabilityCard(vuln) {
    const cweId = vuln.cwe || 'CWE';
    const cweNum = cweId.replace('CWE-', '');
    const cweUrl = `https://cwe.mitre.org/data/definitions/${cweNum}.html`;

    return `
      <div class="cine-finding-item">
        <div class="finding-top-bar">
          <div style="display:flex; align-items:center; gap:10px; font-weight:800; font-size:1.02rem; color:var(--text-pure);">
            <span style="color:var(--cine-amber); font-size:1.3rem;">⚠️</span>
            <span>${this.escapeHtml(vuln.title)}</span>
            <span style="font-size:0.68rem; background:rgba(245,197,24,0.18); color:var(--cine-amber); padding:2px 8px; border-radius:9999px; font-weight:800; border:1px solid rgba(245,197,24,0.4);">
              ${this.escapeHtml(vuln.severity)}
            </span>
          </div>
          <div style="display:flex; gap:8px; align-items:center;">
            <a href="${cweUrl}" target="_blank" rel="noopener" style="font-size:0.75rem; color:var(--cine-cyan); text-decoration:none; font-family:var(--font-mono); font-weight:700; background:rgba(6,182,212,0.1); padding:2px 8px; border-radius:4px; border:1px solid rgba(6,182,212,0.25);" title="Open MITRE Definition">
              ${this.escapeHtml(vuln.cwe)} ↗
            </a>
            <span style="font-family:var(--font-mono); font-size:0.78rem; color:var(--text-muted); background:rgba(255,255,255,0.05); padding:3px 8px; border-radius:6px;">
              ${this.escapeHtml(vuln.file)}:${vuln.line}
            </span>
          </div>
        </div>

        <div style="font-size:0.86rem; color:var(--text-secondary); margin:8px 0; line-height:1.5;">
          ${this.escapeHtml(vuln.description)}
        </div>

        <div class="cine-code-box">
          <code>${this.escapeHtml(vuln.snippet || '')}</code>
        </div>

        <div style="font-size:0.82rem; color:var(--text-primary); margin-top:10px; display:flex; align-items:flex-start; gap:8px;">
          <strong style="color:var(--cine-cyan); flex-shrink:0;">🛡️ Defense Playbook:</strong>
          <span>${this.escapeHtml(vuln.remediation || 'Enforce parameter binding or validate path against root.')}</span>
        </div>
      </div>
    `;
  },

  /**
   * Renders ChromaDB Policy Item.
   */
  renderPolicyCard(policy) {
    const scorePct = Math.round((policy.relevance_score || 0.85) * 100);
    return `
      <div style="background:rgba(14, 16, 22, 0.85); border:1px solid var(--border-glass); border-left:4px solid var(--cine-red); border-radius:var(--radius-md); padding:16px 20px; margin-bottom:14px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <span style="font-weight:800; color:var(--text-pure); font-size:0.95rem;">${this.escapeHtml(policy.title)}</span>
          <span style="font-size:0.72rem; color:var(--cine-cyan); font-family:var(--font-mono); background:rgba(6,182,212,0.1); padding:2px 8px; border-radius:9999px; border:1px solid rgba(6,182,212,0.25);">
            ${scorePct}% Vector Match
          </span>
        </div>
        <p style="font-size:0.84rem; color:var(--text-secondary); line-height:1.5;">${this.escapeHtml(policy.document)}</p>
      </div>
    `;
  },

  /**
   * Renders Interactive Checkable Remediation Checklist.
   */
  renderChecklist(items, auditId, onToggleCallbackName = 'App.toggleTask') {
    if (!items || items.length === 0) {
      return `<div style="color:var(--text-muted); font-size:0.88rem; padding:16px 0;">No active remediation actions required. Safe to deploy!</div>`;
    }

    const total = items.length;
    const completed = items.filter(i => i.completed).length;
    const pct = total === 0 ? 100 : Math.round((completed / total) * 100);

    const itemsHtml = items.map(item => {
      const isDone = Boolean(item.completed);
      const prio = (item.priority || 'HIGH').toLowerCase();
      return `
        <div class="checklist-card-row ${isDone ? 'done' : ''}" id="checklist-row-${item.id}">
          <input 
            type="checkbox" 
            class="checklist-check-input" 
            id="chk-${item.id}" 
            ${isDone ? 'checked' : ''}
            onchange="${onToggleCallbackName}('${auditId}', '${item.id}', this.checked)"
          />
          <div style="flex:1;">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
              <span class="task-title" style="font-size:0.92rem; font-weight:700; color:var(--text-pure);">${this.escapeHtml(item.task)}</span>
              <span style="font-size:0.65rem; font-weight:800; padding:2px 8px; border-radius:9999px; background:rgba(229,9,20,0.15); color:var(--cine-red); border:1px solid rgba(229,9,20,0.3);">
                ${this.escapeHtml(item.priority)}
              </span>
            </div>
            <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:4px; line-height:1.45;">
              ${this.escapeHtml(item.description)}
            </div>
          </div>
        </div>
      `;
    }).join('');

    return `
      <div class="checklist-progress-box">
        <div class="progress-label-row">
          <span>Remediation Status: <strong style="color:#fff;">${completed} of ${total} resolved</strong></span>
          <span style="font-family:var(--font-mono); color:var(--cine-emerald);">${pct}% COMPLETED</span>
        </div>
        <div class="progress-track-bar">
          <div class="progress-fill-bar" style="width: ${pct}%;"></div>
        </div>
      </div>
      <div>
        ${itemsHtml}
      </div>
    `;
  },

  copyToClipboard(text) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => {
        alert('Copied masked secret to clipboard: ' + text);
      }).catch(() => {
        prompt('Copy secret:', text);
      });
    } else {
      prompt('Copy secret:', text);
    }
  }
};

window.Components = Components;
