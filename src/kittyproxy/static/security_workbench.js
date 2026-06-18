(function () {
    'use strict';

    let report = null;
    let selectedFindingId = null;
    let scanStarted = false;
    let regressionSuite = null;

    const byId = (id) => document.getElementById(id);
    const escapeHtml = (value) => String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

    function notify(message, type = 'info') {
        if (typeof showToast === 'function') showToast(message, type);
    }

    function setStatus(message, error = false) {
        const element = byId('sw-scan-status');
        if (!element) return;
        element.textContent = message;
        element.style.color = error ? '#b3261e' : '#777';
    }

    async function scan() {
        const button = byId('sw-scan-btn');
        if (!button || button.disabled) return;
        button.disabled = true;
        const oldHtml = button.innerHTML;
        button.innerHTML = '<span class="material-symbols-outlined">progress_activity</span> Scanning…';
        setStatus('Analyzing captured flows…');
        try {
            const response = await fetch(`${API_BASE}/security-workbench/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    host: byId('sw-host-filter')?.value.trim() || null,
                    limit: 500
                })
            });
            if (!response.ok) {
                const payload = await response.json().catch(() => ({}));
                throw new Error(payload.detail || `HTTP ${response.status}`);
            }
            report = await response.json();
            regressionSuite = null;
            selectedFindingId = report.findings?.[0]?.id || null;
            renderAll();
            const count = report.summary?.total_findings || 0;
            setStatus(`${report.scope?.flow_count || 0} flows · ${report.duration_ms || 0} ms`);
            notify(`Security scan complete: ${count} finding${count === 1 ? '' : 's'}`, count ? 'info' : 'success');
            byId('sw-export-json-btn').disabled = false;
            byId('sw-export-python-btn').disabled = false;
        } catch (error) {
            console.error('[Security Workbench] scan failed', error);
            setStatus(`Scan failed: ${error.message || error}`, true);
            notify('Security Workbench scan failed', 'error');
        } finally {
            button.disabled = false;
            button.innerHTML = oldHtml;
        }
    }

    function filteredFindings() {
        if (!report?.findings) return [];
        const severity = byId('sw-severity-filter')?.value || '';
        const category = byId('sw-category-filter')?.value || '';
        const search = (byId('sw-search-filter')?.value || '').trim().toLowerCase();
        return report.findings.filter((finding) => {
            if (severity && finding.severity !== severity) return false;
            if (category && finding.category !== category) return false;
            if (!search) return true;
            return [
                finding.title,
                finding.rule_id,
                finding.url,
                finding.description,
                ...(finding.asvs || [])
            ].join(' ').toLowerCase().includes(search);
        });
    }

    function renderAll() {
        renderSummary();
        renderFindings();
        renderDetail();
    }

    function renderSummary() {
        const severity = report?.summary?.severity || {};
        byId('sw-critical-count').textContent = severity.critical || 0;
        byId('sw-high-count').textContent = severity.high || 0;
        byId('sw-total-count').textContent = report?.summary?.total_findings || 0;
        byId('sw-flow-count').textContent = report?.scope?.flow_count || 0;
        byId('sw-asvs-count').textContent = report?.asvs?.mapped_requirement_count || 0;
    }

    function renderFindings() {
        const container = byId('sw-findings-list');
        if (!container) return;
        const findings = filteredFindings();
        byId('sw-visible-count').textContent = findings.length;
        if (!findings.length) {
            container.innerHTML = `<div class="sw-empty">${report ? 'No findings match the current filters.' : 'Scan captured browser traffic to build the security map.'}</div>`;
            return;
        }
        if (!findings.some((finding) => finding.id === selectedFindingId)) {
            selectedFindingId = findings[0].id;
        }
        container.innerHTML = findings.map((finding) => `
            <button class="sw-finding ${finding.id === selectedFindingId ? 'active' : ''}" data-finding-id="${escapeHtml(finding.id)}">
                <div class="sw-finding-head">
                    <span class="sw-severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
                    <span class="sw-finding-title">${escapeHtml(finding.title)}</span>
                    <span class="sw-category">${escapeHtml(finding.category)}</span>
                </div>
                <div class="sw-finding-meta">
                    <span>${escapeHtml(finding.rule_id)}</span>
                    <span>${escapeHtml(finding.confidence)} confidence</span>
                    <span>${finding.flow_ids?.length || 0} flow(s)</span>
                </div>
                <div class="sw-finding-url">${escapeHtml(finding.url)}</div>
            </button>
        `).join('');
    }

    function currentFinding() {
        return report?.findings?.find((finding) => finding.id === selectedFindingId) || null;
    }

    function renderDetail(replayResult = null) {
        const pane = byId('sw-detail-pane');
        if (!pane) return;
        const finding = currentFinding();
        if (!finding) {
            pane.innerHTML = `
                <div class="sw-empty sw-detail-empty">
                    <span class="material-symbols-outlined">policy</span>
                    <p>Select a finding to inspect evidence, remediation, ASVS mapping and replay.</p>
                </div>`;
            return;
        }
        const flowId = finding.flow_ids?.[0] || '';
        const asvs = (finding.asvs || []).map((item) => `<span class="sw-asvs-chip">${escapeHtml(item)}</span>`).join('');
        const delta = replayResult?.security_delta;
        const regression = replayResult?.regression;
        const failedChecks = regression?.results?.filter((item) => !item.passed).length || 0;
        const replayHtml = replayResult ? `
            <div class="sw-replay-result ${regression?.passed ? '' : 'failed'}">
                <strong>Replay ${escapeHtml(String(replayResult.response?.status_code || ''))}</strong>
                · ${escapeHtml(String(replayResult.response?.duration_ms || 0))} ms
                · ${regression?.passed ? 'automated assertions passed' : `${failedChecks} assertion(s) still failing`}
                <br>Resolved: ${escapeHtml((delta?.resolved_rules || []).join(', ') || 'none')}
                <br>Persisting: ${escapeHtml((delta?.persisting_rules || []).join(', ') || 'none')}
                <br>New: ${escapeHtml((delta?.new_rules || []).join(', ') || 'none')}
            </div>` : '';
        pane.innerHTML = `
            <div class="sw-detail-header">
                <div>
                    <span class="sw-severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
                    <h3>${escapeHtml(finding.title)}</h3>
                    <div class="sw-detail-rule">${escapeHtml(finding.rule_id)} · ${escapeHtml(finding.category)} · ${escapeHtml(finding.confidence)} confidence</div>
                </div>
                <div class="sw-detail-actions">
                    <button class="btn btn-secondary" data-sw-action="repeater" ${flowId ? '' : 'disabled'}>
                        <span class="material-symbols-outlined" style="font-size:16px;vertical-align:middle;">repeat</span>
                        Repeater
                    </button>
                    <button class="btn btn-primary" data-sw-action="replay" ${flowId ? '' : 'disabled'}>
                        <span class="material-symbols-outlined" style="font-size:16px;vertical-align:middle;">replay</span>
                        Replay & verify
                    </button>
                </div>
            </div>
            <div class="sw-section">
                <h4>Affected target</h4>
                <p><code>${escapeHtml(finding.url)}</code><br>${finding.flow_ids?.length || 0} captured flow(s)</p>
            </div>
            <div class="sw-section">
                <h4>Why it matters</h4>
                <p>${escapeHtml(finding.description)}</p>
            </div>
            <div class="sw-section">
                <h4>Evidence</h4>
                <code class="sw-evidence">${escapeHtml(finding.evidence || 'No body excerpt required for this rule.')}</code>
            </div>
            <div class="sw-section">
                <h4>Actionable remediation</h4>
                <p>${escapeHtml(finding.remediation)}</p>
            </div>
            <div class="sw-section">
                <h4>ASVS 5.0.0 mapping</h4>
                <div class="sw-asvs-list">${asvs || '<span class="sw-asvs-chip">No direct mapping</span>'}</div>
            </div>
            ${replayHtml}
        `;
    }

    async function replayFinding() {
        const finding = currentFinding();
        const flowId = finding?.flow_ids?.[0];
        if (!flowId) return;
        if (typeof showAppConfirm === 'function') {
            const allowed = await showAppConfirm(
                `Replay the captured request for ${finding.url}? This sends network traffic to the target.`,
                { title: 'Replay & verify', confirmText: 'Replay' }
            );
            if (!allowed) return;
        }
        const button = byId('sw-detail-pane')?.querySelector('[data-sw-action="replay"]');
        if (button) button.disabled = true;
        setStatus('Replaying flow and evaluating assertions…');
        try {
            const response = await fetch(`${API_BASE}/security-workbench/replay`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ flow_id: flowId, through_proxy: true })
            });
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
            renderDetail(payload);
            setStatus(`Replay completed in ${payload.response?.duration_ms || 0} ms`);
            notify('Replay and security assertions completed', payload.regression?.passed ? 'success' : 'info');
        } catch (error) {
            console.error('[Security Workbench] replay failed', error);
            setStatus(`Replay failed: ${error.message || error}`, true);
            notify('Security replay failed', 'error');
        } finally {
            if (button) button.disabled = false;
        }
    }

    async function sendToRepeater() {
        const finding = currentFinding();
        const flowId = finding?.flow_ids?.[0];
        if (!flowId) return;
        try {
            const response = await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const flow = await response.json();
            let body = '';
            if (flow.request?.content_bs64) {
                try { body = atob(flow.request.content_bs64); } catch (_) {}
            }
            if (typeof createRepeaterTab !== 'function') throw new Error('Repeater is unavailable');
            createRepeaterTab({
                method: flow.method || 'GET',
                url: flow.url || '',
                headers: JSON.stringify(flow.request?.headers || {}, null, 2),
                body
            });
            document.querySelector('.nav-item[data-view="replay"]')?.click();
            notify('Flow sent to Repeater', 'success');
        } catch (error) {
            console.error('[Security Workbench] send to repeater failed', error);
            notify('Could not send flow to Repeater', 'error');
        }
    }

    async function getRegressionSuite() {
        if (regressionSuite) return regressionSuite;
        const response = await fetch(`${API_BASE}/security-workbench/regression-suite`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                host: byId('sw-host-filter')?.value.trim() || null,
                limit: 500,
                include_sensitive: false
            })
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
        regressionSuite = payload;
        return payload;
    }

    function download(name, content, type) {
        const blob = new Blob([content], { type });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = name;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 0);
    }

    async function exportRegression(format) {
        try {
            setStatus('Generating regression suite…');
            const suite = await getRegressionSuite();
            if (format === 'python') {
                download('test_kittyproxy_browser_security.py', suite.python || '', 'text/x-python');
            } else {
                const jsonSuite = { ...suite };
                delete jsonSuite.python;
                download('kittyproxy-browser-security-regression.json', JSON.stringify(jsonSuite, null, 2), 'application/json');
            }
            setStatus(`${suite.cases?.length || 0} regression case(s) generated`);
            notify('Regression suite exported', 'success');
        } catch (error) {
            console.error('[Security Workbench] export failed', error);
            setStatus(`Export failed: ${error.message || error}`, true);
            notify('Regression export failed', 'error');
        }
    }

    function init() {
        byId('sw-scan-btn')?.addEventListener('click', scan);
        byId('sw-export-json-btn')?.addEventListener('click', () => exportRegression('json'));
        byId('sw-export-python-btn')?.addEventListener('click', () => exportRegression('python'));
        ['sw-severity-filter', 'sw-category-filter', 'sw-search-filter'].forEach((id) => {
            byId(id)?.addEventListener('input', () => {
                renderFindings();
                renderDetail();
            });
        });
        byId('sw-findings-list')?.addEventListener('click', (event) => {
            const item = event.target.closest('[data-finding-id]');
            if (!item) return;
            selectedFindingId = item.dataset.findingId;
            renderFindings();
            renderDetail();
        });
        byId('sw-detail-pane')?.addEventListener('click', (event) => {
            const action = event.target.closest('[data-sw-action]')?.dataset.swAction;
            if (action === 'replay') replayFinding();
            if (action === 'repeater') sendToRepeater();
        });
        document.querySelector('.main-nav')?.addEventListener('click', (event) => {
            const item = event.target.closest('.nav-item[data-view="security-workbench"]');
            if (!item || scanStarted) return;
            scanStarted = true;
            setTimeout(scan, 0);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
