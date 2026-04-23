/**
 * Security Mail Analyzer - Frontend Application
 * NVIDIA GB10 최적화 보안 알람 분석 대시보드
 */

const API_BASE = '';
let currentPage = 'dashboard';
let currentAlertPage = 1;
let chatSessionId = null;
let dashboardCharts = {};

// 상관분석 전역 상태 (알람 목록 페이지 간 유지)
let _corrStatus = { running: false, lastResult: null };
// 시간대 설정 전역 변수 (formatDate에서 사용)
let _appTimezone = 'Asia/Seoul';
let _businessStartHour = 9;
let _businessEndHour = 18;
// 시간대 설정 라이브 시계 타이머
let _tzClockTimer = null;
// 상관분석 폴링 타이머
let _corrPollingTimer = null;

// ============================================================
// 라우팅
// ============================================================
function navigate(page) {
  currentPage = page;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const navEl = document.querySelector(`.nav-item[onclick*="${page}"]`);
  if (navEl) navEl.classList.add('active');
  
  const titles = {
    'dashboard': '📊 대시보드',
    'alerts': '🚨 알람 목록',
    'ip-intel': '🌐 IP 인텔리전스',
    'history': '📋 히스토리',
    'chat': '🤖 AI 분석 채팅',
    'knowledge': '🧠 지식베이스',
    'gmail-config': '📧 Gmail 설정',
    'reports': '📨 리포트 발송',
    'settings': '⚙️ 환경 설정',
  };
  document.getElementById('page-title').textContent = titles[page] || page;
  
  renderPage(page);
}

function refreshCurrentPage() {
  navigate(currentPage);
}

async function renderPage(page) {
  const content = document.getElementById('page-content');
  content.innerHTML = '<div class="loading"><div class="spinner"></div> 로딩 중...</div>';
  
  switch(page) {
    case 'dashboard': await renderDashboard(); break;
    case 'alerts': await renderAlerts(); break;
    case 'ip-intel': await renderIPIntel(); break;
    case 'history': await renderHistory(); break;
    case 'chat': renderChat(); break;
    case 'knowledge': await renderKnowledge(); break;
    case 'gmail-config': await renderGmailConfig(); break;
    case 'reports': await renderReports(); break;
    case 'settings': await renderSettings(); break;
    default: content.innerHTML = '<div class="loading">페이지를 찾을 수 없습니다.</div>';
  }
}

// ============================================================
// API 호출
// ============================================================
async function api(path, method = 'GET', body = null) {
  try {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);
    const resp = await fetch(API_BASE + path, opts);
    const data = await resp.json();
    return data;
  } catch(e) {
    console.error('API Error:', e);
    return { error: e.message };
  }
}

// ============================================================
// 대시보드
// ============================================================
async function renderDashboard() {
  const days = parseInt(document.getElementById('period-select')?.value || 7);
  const stats = await api(`/api/alerts/stats?days=${days}`);
  
  if (stats.error) {
    document.getElementById('page-content').innerHTML = 
      `<div class="loading" style="color:var(--critical)">⚠️ 데이터 로드 오류: ${stats.error}</div>`;
    return;
  }
  
  // 심각도별 통계
  const bySev = stats.by_severity || {};
  const total = stats.total || 0;
  const fpRate = total > 0 ? Math.round((stats.false_positives || 0) / total * 100) : 0;
  
  // 위험도 색상
  const riskColors = {
    critical: 'var(--critical)', high: 'var(--high)', 
    medium: 'var(--medium)', low: 'var(--low)', unknown: 'var(--text-muted)'
  };
  
  // 최근 알람 행 생성
  const recentRows = (stats.recent_alerts || []).map(a => `
    <tr style="cursor:pointer" onclick="showAlertDetail(${a.id})">
      <td>${formatDate(a.received_at)}</td>
      <td>${severityBadge(a.severity)}</td>
      <td style="max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escHtml(a.subject || '')}">
        ${escHtml(a.subject || '')}
        ${a.is_false_positive ? '<span class="badge badge-fp" style="margin-left:4px;">오탐</span>' : ''}
        ${a.is_repeated ? '<span class="badge badge-rep" style="margin-left:4px;">반복</span>' : ''}
      </td>
      <td>${(a.extracted_ips || []).slice(0,2).map(ip => 
        `<span class="ip-chip" onclick="event.stopPropagation();lookupIP('${ip}')">${ip}</span>`
      ).join('')}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-muted);font-size:12px;">
        ${escHtml((a.llm_summary || '미분석'))}
      </td>
    </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">해당 기간 알람 없음</td></tr>';
  
  // 상위 IP 행
  const topIPRows = (stats.top_threat_ips || []).map(ip => `
    <tr style="cursor:pointer" onclick="lookupIP('${ip.ip}')">
      <td><span class="ip-chip">${ip.ip}</span></td>
      <td>${ip.country || '-'}</td>
      <td style="color:var(--text-muted);font-size:12px;">${ip.isp || '-'}</td>
      <td>
        <div class="threat-score">
          <span style="color:${ip.threat_score > 70 ? 'var(--critical)' : ip.threat_score > 40 ? 'var(--high)' : 'var(--low)'};font-weight:bold;">${ip.threat_score || 0}</span>
          <div class="threat-bar" style="width:80px;">
            <div class="threat-fill" style="width:${ip.threat_score || 0}%;background:${ip.threat_score > 70 ? 'var(--critical)' : ip.threat_score > 40 ? 'var(--high)' : 'var(--low)'}"></div>
          </div>
        </div>
      </td>
      <td style="color:var(--accent-cyan);font-weight:bold;">${ip.alert_count || 0}</td>
    </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px;">탐지된 위협 IP 없음</td></tr>';
  
  // 알람 유형
  const typeItems = Object.entries(stats.by_type || {}).slice(0, 5).map(([type, count]) => `
    <div style="margin-bottom:10px;">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
        <span style="font-size:12px;color:var(--text-secondary);">${type.slice(0,40)}</span>
        <span style="font-size:12px;font-weight:bold;color:var(--text-primary);">${count}</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill" style="width:${Math.round(count/Math.max(total,1)*100)}%"></div>
      </div>
    </div>`).join('') || '<p style="color:var(--text-muted);font-size:13px;">분류된 유형 없음</p>';
  
  document.getElementById('page-content').innerHTML = `
    <!-- 통계 카드 -->
    <div class="stats-grid">
      <div class="stat-card total">
        <div class="stat-value">${total}</div>
        <div class="stat-label">전체 알람</div>
      </div>
      <div class="stat-card critical">
        <div class="stat-value">${bySev.critical || 0}</div>
        <div class="stat-label">CRITICAL</div>
      </div>
      <div class="stat-card high">
        <div class="stat-value">${bySev.high || 0}</div>
        <div class="stat-label">HIGH</div>
      </div>
      <div class="stat-card medium">
        <div class="stat-value">${bySev.medium || 0}</div>
        <div class="stat-label">MEDIUM</div>
      </div>
      <div class="stat-card low">
        <div class="stat-value">${(bySev.low || 0) + (bySev.info || 0)}</div>
        <div class="stat-label">LOW/INFO</div>
      </div>
      <div class="stat-card fp">
        <div class="stat-value">${stats.false_positives || 0}</div>
        <div class="stat-label">오탐 (${fpRate}%)</div>
      </div>
      <div class="stat-card repeated">
        <div class="stat-value">${stats.repeated || 0}</div>
        <div class="stat-label">반복 알람</div>
      </div>
    </div>
    
    <div class="grid-2">
      <!-- 차트 -->
      <div class="card">
        <div class="card-title">📈 심각도 분포</div>
        <div class="chart-container">
          <canvas id="severity-chart"></canvas>
        </div>
      </div>
      
      <!-- 알람 유형 -->
      <div class="card">
        <div class="card-title">📋 알람 유형 Top 5</div>
        ${typeItems}
      </div>
    </div>
    
    <!-- 최근 알람 -->
    <div class="card">
      <div class="card-title">
        🚨 최근 알람 
        <span style="margin-left:auto;">
          <button class="btn btn-primary btn-sm" onclick="navigate('alerts')">전체 보기 →</button>
        </span>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>수신시간</th><th>심각도</th><th>제목</th><th>IP</th><th>AI 요약</th>
            </tr>
          </thead>
          <tbody>${recentRows}</tbody>
        </table>
      </div>
    </div>
    
    <!-- 위협 IP -->
    <div class="card">
      <div class="card-title">
        🌐 상위 위협 IP
        <span style="margin-left:auto;">
          <button class="btn btn-secondary btn-sm" onclick="navigate('ip-intel')">IP 인텔리전스 →</button>
        </span>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr><th>IP 주소</th><th>국가</th><th>ISP</th><th>위협 점수</th><th>탐지 횟수</th></tr>
          </thead>
          <tbody>${topIPRows}</tbody>
        </table>
      </div>
    </div>
  `;
  
  // 차트 렌더링
  renderSeverityChart(bySev);
}

function renderSeverityChart(bySev) {
  const ctx = document.getElementById('severity-chart');
  if (!ctx) return;
  
  if (dashboardCharts.severity) {
    dashboardCharts.severity.destroy();
  }
  
  dashboardCharts.severity = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
      datasets: [{
        data: [bySev.critical || 0, bySev.high || 0, bySev.medium || 0, bySev.low || 0, bySev.info || 0],
        backgroundColor: ['#ef233c', '#fb8500', '#ffd60a', '#06d6a0', '#4cc9f0'],
        borderColor: '#1e2235',
        borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: '#9fa8da', font: { size: 12 } }
        }
      }
    }
  });
}

async function updateDashboard() {
  if (currentPage === 'dashboard') {
    await renderDashboard();
  }
}

// ============================================================
// 알람 목록
// ============================================================
// 알람 필터 상태 (페이지 전환해도 유지)
const _alertFilter = { severity: '', status: '', fp: '', search: '', days: '30' };

async function renderAlerts(page = 1) {
  currentAlertPage = page;

  // 필터바가 이미 존재하면 현재 값 읽기, 없으면 저장된 상태 사용
  const filterBar = document.getElementById('alerts-filter-bar');
  if (filterBar) {
    _alertFilter.severity = document.getElementById('filter-severity')?.value || '';
    _alertFilter.status   = document.getElementById('filter-status')?.value   || '';
    _alertFilter.fp       = document.getElementById('filter-fp')?.value       || '';
    _alertFilter.search   = document.getElementById('filter-search')?.value   || '';
    _alertFilter.days     = document.getElementById('filter-days')?.value     || '30';
  }

  const { severity, status, fp, search, days } = _alertFilter;

  const params = new URLSearchParams({ page, limit: 25, days });
  if (severity) params.set('severity', severity);
  if (status)   params.set('status', status);
  if (fp)       params.set('is_false_positive', fp);
  if (search)   params.set('search', search);

  const data = await api(`/api/alerts?${params}`);

  const rows = (data.alerts || []).map(a => `
    <tr style="cursor:pointer;" onclick="showAlertDetail(${a.id})">
      <td style="color:var(--text-muted);font-size:12px;white-space:nowrap;">${formatDate(a.received_at)}</td>
      <td>${severityBadge(a.severity)}</td>
      <td>
        <div style="display:flex;flex-direction:column;gap:2px;">
          <span style="font-size:13px;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:350px;" title="${escHtml(a.subject || '')}">
            ${escHtml(a.subject || '(제목 없음)')}
          </span>
          <span style="font-size:11px;color:var(--text-muted);">${escHtml(a.sender || '')}</span>
        </div>
      </td>
      <td>
        ${a.is_false_positive ? '<span class="badge badge-fp">오탐</span>' : ''}
        ${a.is_repeated ? `<span class="badge badge-rep">반복 ${a.repeat_count || 1}회</span>` : ''}
        ${a.after_hours_access ? '<span class="badge" style="background:rgba(255,140,0,0.2);color:#ffa500;border:1px solid rgba(255,140,0,0.4);">🌙야간</span>' : ''}
      </td>
      <td>
        ${(a.extracted_ips || []).slice(0,2).map(ip =>
          `<span class="ip-chip" onclick="event.stopPropagation();lookupIP('${ip}')">${ip}</span>`
        ).join('')}
      </td>
      <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--text-muted);">
        ${escHtml(a.llm_summary || '')}
      </td>
      <td>${statusBadge(a.status)}</td>
      <td onclick="event.stopPropagation()">
        <div style="display:flex;gap:4px;">
          <button class="btn btn-secondary btn-sm" onclick="reanalyzeAlert(${a.id})">🔄</button>
          <button class="btn btn-secondary btn-sm" onclick="showFeedbackModal(${a.id})">✏️</button>
        </div>
      </td>
    </tr>`).join('') || '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:30px;">알람이 없습니다</td></tr>';

  const totalPages = data.pages || 1;
  const paginationHtml = generatePagination(page, totalPages, 'renderAlerts');

  // 필터바가 없을 때만 전체 레이아웃 렌더링 (최초 1회)
  if (!document.getElementById('alerts-filter-bar')) {
    document.getElementById('page-content').innerHTML = `
      <div class="card" style="margin-bottom:16px;">
        <div class="filter-bar" id="alerts-filter-bar">
          <input class="form-input" id="filter-search" placeholder="🔍 검색..." style="width:200px;" onkeydown="if(event.key==='Enter')renderAlerts(1)">
          <select class="form-select" id="filter-severity" style="width:120px;" onchange="renderAlerts(1)">
            <option value="">모든 심각도</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select class="form-select" id="filter-fp" style="width:110px;" onchange="renderAlerts(1)">
            <option value="">오탐 전체</option>
            <option value="false">실제 위협</option>
            <option value="true">오탐</option>
          </select>
          <select class="form-select" id="filter-status" style="width:110px;" onchange="renderAlerts(1)">
            <option value="">모든 상태</option>
            <option value="new">신규</option>
            <option value="analyzed">분석완료</option>
            <option value="closed">종료</option>
          </select>
          <select class="form-select" id="filter-days" style="width:80px;" onchange="renderAlerts(1)">
            <option value="7">7일</option>
            <option value="30">30일</option>
            <option value="90">90일</option>
            <option value="365">365일</option>
          </select>
          <button class="btn btn-primary btn-sm" onclick="renderAlerts(1)">적용</button>
          <button class="btn btn-secondary btn-sm" onclick="resetAlertFilters()">🔄 초기화</button>
          <button class="btn btn-secondary btn-sm" onclick="analyzeAllPending()" title="미분석 알람 일괄 분석">🤖 일괄분석</button>
          <button class="btn btn-secondary btn-sm" id="corr-btn" onclick="showCorrelationModal()" title="알람 상관분석 (2차 침해·횡전개·APT 탐지)">🕸 상관분석</button>
          <span id="alerts-total-badge" style="margin-left:auto;color:var(--text-muted);font-size:12px;"></span>
        </div>
        <div id="corr-status-bar" style="display:none;margin-top:8px;padding:8px 12px;background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;font-size:12px;"></div>
      </div>
      <div class="card">
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>수신시간</th><th>심각도</th><th>제목 / 발신자</th><th>분류</th>
                <th>탐지 IP</th><th>AI 요약</th><th>상태</th><th>액션</th>
              </tr>
            </thead>
            <tbody id="alerts-tbody"></tbody>
          </table>
        </div>
        <div id="alerts-pagination"></div>
      </div>`;

    // 저장된 필터값 복원
    document.getElementById('filter-severity').value = _alertFilter.severity;
    document.getElementById('filter-fp').value       = _alertFilter.fp;
    document.getElementById('filter-status').value   = _alertFilter.status;
    document.getElementById('filter-days').value     = _alertFilter.days;
    document.getElementById('filter-search').value   = _alertFilter.search;
  }

  // 테이블 내용과 페이지네이션만 업데이트 (필터바 DOM 유지)
  document.getElementById('alerts-tbody').innerHTML = rows;
  document.getElementById('alerts-pagination').innerHTML = paginationHtml;
  document.getElementById('alerts-total-badge').textContent = `총 ${data.total || 0}건`;

  // 상관분석 상태바 복원
  _updateCorrStatusBar();
}

// ============================================================
// 알람 상세
// ============================================================
async function showAlertDetail(alertId) {
  const alert = await api(`/api/alerts/${alertId}`);
  if (alert.error) { showToast('알람 정보를 불러올 수 없습니다.', 'error'); return; }
  
  const ipChips = (alert.extracted_ips || []).map(ip => 
    `<span class="ip-chip" onclick="lookupIP('${ip}')">${ip}</span>`
  ).join('');
  
  const domainChips = (alert.extracted_domains || []).map(d => 
    `<span style="display:inline-block;padding:3px 8px;background:rgba(67,97,238,0.1);color:#748ffc;border-radius:4px;font-size:12px;margin:2px;">${d}</span>`
  ).join('');
  
  const relatedAlerts = (alert.related_alerts || []).map(ra => `
    <div style="padding:8px;background:var(--bg-primary);border-radius:6px;margin-bottom:6px;cursor:pointer;" onclick="showAlertDetail(${ra.id})">
      <div style="font-size:12px;color:var(--text-secondary);">${formatDate(ra.received_at)} ${severityBadge(ra.severity)}</div>
      <div style="font-size:13px;margin-top:2px;">${escHtml(ra.subject || '')}</div>
    </div>`).join('');
  
  openModal(`
    <div class="modal-header">
      <div>
        <div class="modal-title">${escHtml(alert.subject || '알람 상세')}</div>
        <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;">
          ${severityBadge(alert.severity)}
          ${alert.is_false_positive ? '<span class="badge badge-fp">오탐</span>' : ''}
          ${alert.is_repeated ? `<span class="badge badge-rep">반복 ${alert.repeat_count || 1}회</span>` : ''}
          ${alert.after_hours_access ? '<span class="badge" style="background:rgba(255,140,0,0.2);color:#ffa500;border:1px solid rgba(255,140,0,0.4);">🌙 시간외</span>' : ''}
          ${statusBadge(alert.status)}
        </div>
      </div>
      <button class="modal-close" onclick="closeModal()">×</button>
    </div>
    
    <div class="detail-section">
      <div class="detail-title">📧 메일 정보</div>
      <div class="detail-content" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
        <div><span style="color:var(--text-muted);">발신자:</span> ${escHtml(alert.sender || '-')}</div>
        <div><span style="color:var(--text-muted);">수신시간:</span> ${formatDateFull(alert.received_at)} ${alert.after_hours_access ? '<span style="color:#ffa500;font-size:11px;">🌙 업무시간 외</span>' : ''}</div>
        <div><span style="color:var(--text-muted);">수신자:</span> ${escHtml(alert.recipient || '-')}</div>
        <div><span style="color:var(--text-muted);">알람 유형:</span> ${escHtml(alert.alert_type || '-')}</div>
      </div>
    </div>
    
    ${alert.extracted_ips?.length ? `
    <div class="detail-section">
      <div class="detail-title">🌐 탐지된 IP (클릭하면 상세 조회)</div>
      <div>${ipChips}</div>
    </div>` : ''}
    
    ${alert.extracted_domains?.length ? `
    <div class="detail-section">
      <div class="detail-title">🔗 탐지된 도메인</div>
      <div>${domainChips}</div>
    </div>` : ''}
    
    ${alert.llm_summary ? `
    <div class="detail-section">
      <div class="detail-title">🤖 AI 분석 결과</div>
      <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:14px;">
        <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:10px;">
          📝 요약
        </div>
        <div class="detail-content">${escHtml(alert.llm_summary || '')}</div>
        
        ${alert.llm_analysis ? `
        <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin:12px 0 8px;">
          🔍 상세 분석
        </div>
        <div class="detail-content">${escHtml(alert.llm_analysis || '')}</div>` : ''}
        
        ${alert.llm_recommendation ? `
        <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin:12px 0 8px;">
          💡 권고사항
        </div>
        <div class="detail-content" style="color:var(--accent-green);">${escHtml(alert.llm_recommendation || '')}</div>` : ''}
        
        ${alert.after_hours_access ? `
        <div style="margin-top:12px;padding:10px;background:rgba(255,140,0,0.1);border-radius:6px;border:1px solid rgba(255,140,0,0.3);">
          <span style="color:#ffa500;font-size:12px;font-weight:600;">🌙 시간외 접속 감지</span>
          <div class="detail-content" style="margin-top:4px;color:var(--text-secondary);">${escHtml(alert.llm_analysis?.includes('시간외') || alert.llm_analysis?.includes('야간') || alert.llm_analysis?.includes('주말') ? (alert.llm_analysis.match(/[^.]*(?:시간외|야간|주말)[^.]*\.?/)?.[0] || '업무시간 외 발생 알람입니다.') : '업무시간 외(야간/주말) 발생 알람입니다. 추가 확인이 필요합니다.')}</div>
        </div>` : ''}
        ${alert.is_false_positive && alert.false_positive_reason ? `
        <div style="margin-top:12px;padding:10px;background:rgba(123,45,139,0.1);border-radius:6px;border:1px solid rgba(123,45,139,0.3);">
          <span style="color:#c77dff;font-size:12px;font-weight:600;">⚠️ 오탐 이유:</span>
          <div class="detail-content" style="margin-top:4px;">${escHtml(alert.false_positive_reason || '')}</div>
        </div>` : ''}
      </div>
    </div>` : ''}
    
    ${relatedAlerts ? `
    <div class="detail-section">
      <div class="detail-title">🔗 관련 알람 (반복 패턴)</div>
      ${relatedAlerts}
    </div>` : ''}
    
    <div class="detail-section">
      <div class="detail-title">📄 원본 내용 (일부)</div>
      <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:6px;padding:12px;font-size:12px;color:var(--text-muted);max-height:200px;overflow-y:auto;white-space:pre-wrap;font-family:monospace;">
        ${escHtml((alert.body_text || '내용 없음').slice(0, 2000))}
      </div>
    </div>
    
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <button class="btn btn-primary" onclick="reanalyzeAlert(${alert.id});closeModal()">🔄 재분석</button>
      <button class="btn btn-secondary" onclick="showFeedbackModal(${alert.id});closeModal()">✏️ 피드백</button>
      <button class="btn btn-secondary" onclick="openChatWithContext(${alert.id});closeModal()">🤖 AI 질의</button>
      <button class="btn btn-danger btn-sm" onclick="if(confirm('삭제하시겠습니까?'))deleteAlert(${alert.id});closeModal()">🗑️ 삭제</button>
    </div>
  `);
}

// ============================================================
// 피드백 모달
// ============================================================
function showFeedbackModal(alertId) {
  openModal(`
    <div class="modal-header">
      <div class="modal-title">✏️ 알람 피드백</div>
      <button class="modal-close" onclick="closeModal()">×</button>
    </div>
    
    <div class="form-group">
      <label class="form-label">심각도 수정</label>
      <select class="form-select" id="feedback-severity">
        <option value="">변경 안함</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
    </div>
    
    <div class="form-group">
      <label class="form-label">오탐 여부</label>
      <select class="form-select" id="feedback-fp">
        <option value="">변경 안함</option>
        <option value="true">오탐 (False Positive)</option>
        <option value="false">실제 위협</option>
      </select>
    </div>
    
    <div class="form-group">
      <label class="form-label">오탐 이유 (오탐인 경우)</label>
      <input class="form-input" id="feedback-fp-reason" placeholder="오탐 이유를 입력하세요">
    </div>
    
    <div class="form-group">
      <label class="form-label">상태</label>
      <select class="form-select" id="feedback-status">
        <option value="">변경 안함</option>
        <option value="new">신규</option>
        <option value="analyzed">분석완료</option>
        <option value="closed">종료</option>
      </select>
    </div>
    
    <div class="form-group">
      <label class="form-label">피드백 내용 (AI 학습에 활용)</label>
      <textarea class="form-textarea" id="feedback-text" placeholder="이 알람에 대한 의견을 입력하세요. AI가 학습하여 향후 유사한 알람을 더 정확히 분석합니다."></textarea>
    </div>
    
    <button class="btn btn-primary" onclick="submitFeedback(${alertId})">
      ✅ 피드백 저장 및 AI 학습
    </button>
  `);
}

async function submitFeedback(alertId) {
  const severity = document.getElementById('feedback-severity')?.value;
  const fp = document.getElementById('feedback-fp')?.value;
  const fpReason = document.getElementById('feedback-fp-reason')?.value;
  const status = document.getElementById('feedback-status')?.value;
  const feedbackText = document.getElementById('feedback-text')?.value;
  
  const payload = {};
  if (severity) payload.severity = severity;
  if (fp !== '') payload.is_false_positive = fp === 'true';
  if (fpReason) payload.false_positive_reason = fpReason;
  if (status) payload.status = status;
  if (feedbackText) payload.feedback_text = feedbackText;
  
  const result = await api(`/api/alerts/${alertId}/feedback`, 'PATCH', payload);
  if (result.success) {
    showToast('✅ 피드백이 저장되고 AI가 학습했습니다.', 'success');
    closeModal();
  } else {
    showToast('피드백 저장 실패: ' + (result.error || ''), 'error');
  }
}

// ============================================================
// IP 인텔리전스
// ============================================================
async function renderIPIntel() {
  const data = await api('/api/ip/threats?limit=50');
  
  const rows = (data.ips || []).map(ip => `
    <tr style="cursor:pointer" onclick="lookupIP('${ip.ip}')">
      <td><span class="ip-chip">${ip.ip}</span></td>
      <td>${ip.country || '-'}</td>
      <td style="font-size:12px;color:var(--text-muted);">${ip.isp || '-'}</td>
      <td>
        <div class="threat-score">
          <span style="font-weight:bold;color:${ip.threat_score > 70 ? 'var(--critical)' : ip.threat_score > 40 ? 'var(--high)' : 'var(--low)'};min-width:30px;">${ip.threat_score}</span>
          <div class="threat-bar" style="width:80px;">
            <div class="threat-fill" style="width:${ip.threat_score}%;background:${ip.threat_score > 70 ? 'var(--critical)' : ip.threat_score > 40 ? 'var(--high)' : 'var(--low)'}"></div>
          </div>
        </div>
      </td>
      <td style="color:var(--accent-orange);font-weight:bold;">${ip.abuse_confidence || 0}%</td>
      <td>
        ${ip.is_tor ? '<span class="badge badge-critical">TOR</span>' : ''}
        ${ip.is_proxy ? '<span class="badge badge-high">PROXY</span>' : ''}
        ${ip.is_datacenter ? '<span class="badge badge-info">DC</span>' : ''}
      </td>
      <td style="color:var(--accent-cyan);font-weight:bold;">${ip.alert_count || 0}</td>
      <td style="font-size:11px;color:var(--text-muted);">${formatDate(ip.last_seen)}</td>
    </tr>`).join('') || '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:30px;">위협 IP 데이터 없음</td></tr>';
  
  document.getElementById('page-content').innerHTML = `
    <div class="card" style="margin-bottom:16px;">
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
        <input class="form-input" id="ip-search" placeholder="IP 주소 직접 조회..." style="width:200px;">
        <button class="btn btn-primary" onclick="lookupIPFromInput()">🔍 조회</button>
        <button class="btn btn-secondary" onclick="showBulkLookup()">📋 일괄 조회</button>
      </div>
    </div>
    
    <div class="card">
      <div class="card-title">🌐 위협 IP 데이터베이스 (${data.total || 0}개)</div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>IP 주소</th><th>국가</th><th>ISP</th><th>위협 점수</th>
              <th>AbuseIPDB</th><th>유형</th><th>탐지 횟수</th><th>마지막 탐지</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `;
}

async function lookupIPFromInput() {
  const ip = document.getElementById('ip-search')?.value?.trim();
  if (ip) lookupIP(ip);
}

async function lookupIP(ip) {
  openModal(`
    <div class="modal-header">
      <div class="modal-title">🌐 IP 상세 조회: <span style="font-family:monospace;color:var(--accent-cyan);">${ip}</span></div>
      <button class="modal-close" onclick="closeModal()">×</button>
    </div>
    <div class="loading"><div class="spinner"></div> IP 정보 조회 중...</div>
  `);
  
  const data = await api(`/api/ip/lookup/${ip}`);
  
  if (data.error) {
    document.querySelector('.modal .loading').innerHTML = `<span style="color:var(--critical);">조회 오류: ${data.error}</span>`;
    return;
  }
  
  const geo = data.geo || {};
  const threat = data.threat || {};
  const links = data.links || {};
  const ts = data.threat_score || 0;
  
  const tsColor = ts > 70 ? 'var(--critical)' : ts > 40 ? 'var(--high)' : ts > 20 ? 'var(--medium)' : 'var(--low)';
  
  const relatedAlerts = (data.related_alerts || []).slice(0, 5).map(a => `
    <div style="padding:8px;background:var(--bg-primary);border-radius:6px;margin-bottom:4px;cursor:pointer;" onclick="showAlertDetail(${a.id})">
      <div style="display:flex;gap:8px;align-items:center;">
        ${severityBadge(a.severity)}
        <span style="font-size:12px;color:var(--text-secondary);">${escHtml(a.subject || '')}</span>
        <span style="margin-left:auto;font-size:11px;color:var(--text-muted);">${formatDate(a.received_at)}</span>
      </div>
    </div>`).join('');
  
  document.getElementById('modal-content').innerHTML = `
    <div class="modal-header">
      <div>
        <div class="modal-title">🌐 IP 상세: <span style="font-family:monospace;color:var(--accent-cyan);">${ip}</span></div>
        <div style="margin-top:6px;">
          ${threat.is_tor ? '<span class="badge badge-critical">TOR</span>' : ''}
          ${geo.is_proxy ? '<span class="badge badge-high">PROXY</span>' : ''}
          ${geo.is_datacenter ? '<span class="badge badge-info">데이터센터</span>' : ''}
        </div>
      </div>
      <button class="modal-close" onclick="closeModal()">×</button>
    </div>
    
    <!-- 위협 점수 -->
    <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px;">
      <div style="display:flex;align-items:center;gap:16px;">
        <div style="text-align:center;">
          <div style="font-size:48px;font-weight:bold;color:${tsColor};">${ts}</div>
          <div style="font-size:11px;color:var(--text-muted);">위협 점수</div>
        </div>
        <div style="flex:1;">
          <div class="threat-bar" style="height:12px;">
            <div class="threat-fill" style="width:${ts}%;background:${tsColor};"></div>
          </div>
          <div style="margin-top:8px;display:flex;gap:12px;font-size:12px;color:var(--text-muted);">
            <span>AbuseIPDB: <strong style="color:var(--text-primary);">${threat.abuse_confidence || 0}%</strong></span>
            <span>탐지 횟수: <strong style="color:var(--accent-cyan);">${data.related_alert_count || 0}회</strong></span>
          </div>
        </div>
      </div>
    </div>
    
    <!-- 지리 정보 -->
    <div class="ip-info-grid" style="margin-bottom:16px;">
      <div class="ip-info-item">
        <div class="ip-info-label">🌍 국가</div>
        <div class="ip-info-value">${geo.country || '-'} ${geo.country_code ? `(${geo.country_code})` : ''}</div>
      </div>
      <div class="ip-info-item">
        <div class="ip-info-label">📍 도시/지역</div>
        <div class="ip-info-value">${geo.city || '-'}, ${geo.region || '-'}</div>
      </div>
      <div class="ip-info-item">
        <div class="ip-info-label">🏢 ISP</div>
        <div class="ip-info-value">${geo.isp || '-'}</div>
      </div>
      <div class="ip-info-item">
        <div class="ip-info-label">🔌 ASN</div>
        <div class="ip-info-value">${geo.asn || '-'}</div>
      </div>
      <div class="ip-info-item">
        <div class="ip-info-label">🏛️ 조직</div>
        <div class="ip-info-value">${geo.org || '-'}</div>
      </div>
      <div class="ip-info-item">
        <div class="ip-info-label">⏰ 마지막 신고</div>
        <div class="ip-info-value">${formatDate(threat.last_reported) || '-'}</div>
      </div>
    </div>
    
    <!-- 외부 링크 -->
    <div style="margin-bottom:16px;">
      <div class="detail-title" style="margin-bottom:8px;">🔗 외부 조회</div>
      <div>
        ${Object.entries(links).map(([name, url]) => 
          `<a class="ext-link" href="${url}" target="_blank" rel="noopener">🔗 ${name.charAt(0).toUpperCase() + name.slice(1)}</a>`
        ).join('')}
      </div>
    </div>
    
    <!-- 관련 알람 -->
    ${relatedAlerts ? `
    <div>
      <div class="detail-title" style="margin-bottom:8px;">🚨 관련 알람 (${data.related_alert_count || 0}건)</div>
      ${relatedAlerts}
      ${data.related_alert_count > 5 ? `<div style="text-align:center;font-size:12px;color:var(--text-muted);margin-top:8px;">+${data.related_alert_count - 5}건 더...</div>` : ''}
    </div>` : ''}
  `;
}

function showBulkLookup() {
  openModal(`
    <div class="modal-header">
      <div class="modal-title">📋 IP 일괄 조회</div>
      <button class="modal-close" onclick="closeModal()">×</button>
    </div>
    <div class="form-group">
      <label class="form-label">IP 주소 목록 (줄바꿈으로 구분, 최대 20개)</label>
      <textarea class="form-textarea" id="bulk-ips" placeholder="1.2.3.4&#10;5.6.7.8&#10;..."></textarea>
    </div>
    <button class="btn btn-primary" onclick="executeBulkLookup()">🔍 일괄 조회</button>
    <div id="bulk-result" style="margin-top:16px;"></div>
  `);
}

async function executeBulkLookup() {
  const text = document.getElementById('bulk-ips')?.value || '';
  const ips = text.split('\n').map(ip => ip.trim()).filter(ip => ip);
  
  if (!ips.length) { showToast('IP를 입력해주세요', 'warning'); return; }
  
  document.getElementById('bulk-result').innerHTML = '<div class="loading"><div class="spinner"></div> 조회 중...</div>';
  
  const result = await api('/api/ip/bulk-lookup', 'POST', { ips });
  const results = result.results || {};
  
  const rows = Object.entries(results).map(([ip, data]) => `
    <tr>
      <td><span class="ip-chip" onclick="lookupIP('${ip}')">${ip}</span></td>
      <td>${data.geo?.country || '-'}</td>
      <td>${data.geo?.isp || '-'}</td>
      <td style="color:${(data.threat_score||0) > 70 ? 'var(--critical)' : 'var(--low)'};">${data.threat_score || 0}</td>
      <td>${data.threat?.abuse_confidence || 0}%</td>
    </tr>`).join('');
  
  document.getElementById('bulk-result').innerHTML = `
    <table>
      <thead><tr><th>IP</th><th>국가</th><th>ISP</th><th>위협점수</th><th>AbuseIPDB</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

// ============================================================
// 히스토리
// ============================================================
async function renderHistory() {
  const days = 90;
  const data = await api(`/api/alerts?days=${days}&limit=100&page=1`);
  
  // 날짜별 그룹화
  const byDate = {};
  (data.alerts || []).forEach(a => {
    const dateKey = a.received_at ? a.received_at.slice(0, 10) : 'unknown';
    if (!byDate[dateKey]) byDate[dateKey] = [];
    byDate[dateKey].push(a);
  });
  
  const dateGroups = Object.entries(byDate).sort(([a], [b]) => b.localeCompare(a)).map(([date, alerts]) => `
    <div class="card" style="margin-bottom:12px;">
      <div class="card-title">
        📅 ${date}
        <span style="margin-left:12px;font-size:12px;font-weight:normal;color:var(--text-muted);">
          총 ${alerts.length}건 | 
          <span style="color:var(--critical);">C: ${alerts.filter(a=>a.severity==='critical').length}</span> |
          <span style="color:var(--high);">H: ${alerts.filter(a=>a.severity==='high').length}</span> |
          <span style="color:var(--medium);">M: ${alerts.filter(a=>a.severity==='medium').length}</span>
        </span>
      </div>
      <div class="table-container">
        <table>
          <thead><tr><th>시간</th><th>심각도</th><th>제목</th><th>분류</th><th>IP</th></tr></thead>
          <tbody>
            ${alerts.map(a => `
              <tr style="cursor:pointer" onclick="showAlertDetail(${a.id})">
                <td style="font-size:12px;color:var(--text-muted);">${(a.received_at || '').slice(11, 19)}</td>
                <td>${severityBadge(a.severity)}</td>
                <td style="font-size:13px;">${escHtml(a.subject || '')}</td>
                <td>
                  ${a.is_false_positive ? '<span class="badge badge-fp">오탐</span>' : ''}
                  ${a.is_repeated ? '<span class="badge badge-rep">반복</span>' : ''}
                </td>
                <td>${(a.extracted_ips||[]).slice(0,2).map(ip=>`<span class="ip-chip" onclick="event.stopPropagation();lookupIP('${ip}')">${ip}</span>`).join('')}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `).join('');
  
  document.getElementById('page-content').innerHTML = `
    <div class="card" style="margin-bottom:16px;">
      <div style="font-size:13px;color:var(--text-secondary);">
        최근 90일 알람 히스토리 | 총 <strong style="color:var(--text-primary);">${data.total || 0}</strong>건
      </div>
    </div>
    ${dateGroups || '<div class="loading" style="color:var(--text-muted);">히스토리가 없습니다</div>'}
  `;
}

// ============================================================
// AI 채팅
// ============================================================
// 채팅 컨텍스트: 분석 기간 (일)
let _chatContextDays = 7;

async function renderChat() {
  if (!chatSessionId) {
    chatSessionId = 'session_' + Date.now();
  }

  // DB 컨텍스트 미리 로드 (통계 표시용)
  const dbCtx = await api('/api/llm/db-context?days=7').catch(() => ({}));
  const total = dbCtx.total || 0;
  const sev = dbCtx.sev_stats || {};
  const ctxBadge = total > 0
    ? `<span style="font-size:11px;background:rgba(6,214,160,0.15);color:var(--accent-green);border:1px solid rgba(6,214,160,0.3);border-radius:4px;padding:2px 8px;">
        📊 DB 연결: ${total}건 (C:${sev.critical||0} H:${sev.high||0} M:${sev.medium||0})
       </span>`
    : `<span style="font-size:11px;background:rgba(255,200,0,0.1);color:#ffa500;border:1px solid rgba(255,200,0,0.3);border-radius:4px;padding:2px 8px;">
        ⚠️ 분석된 알람 없음 (수집 후 LLM 분석 필요)
       </span>`;

  const quickQuestions = [
    { icon: '🚨', text: '지금 가장 위험한 알람은 무엇인가요?', q: '현재 DB에 있는 알람 중 가장 위험한 것은 무엇인가요? Critical/High 알람을 중심으로 설명해주세요.' },
    { icon: '📊', text: '최근 7일 보안 현황 요약', q: '최근 7일간의 보안 알람 현황을 요약해주세요. 심각도별 분포, 주요 위협, 오탐 현황을 포함해주세요.' },
    { icon: '🔄', text: '반복 알람 패턴 분석', q: '반복적으로 발생하는 알람의 패턴을 분석해주세요. 원인과 해결 방안도 알려주세요.' },
    { icon: '🌙', text: '야간 알람 분석', q: '업무시간 외(야간/주말) 발생한 알람을 분석해주세요. 이상 접속 여부와 대응 방안을 알려주세요.' },
    { icon: '🌐', text: '위협 IP 분석', q: '탐지된 위협 IP 목록을 분석해주세요. 어떤 공격 패턴인지, 차단해야 할 IP는 무엇인지 알려주세요.' },
    { icon: '❓', text: '오탐 줄이는 방법', q: '현재 오탐(False Positive) 알람을 줄이는 방법을 알려주세요. 현재 오탐 패턴도 분석해주세요.' },
    { icon: '🛡️', text: '즉각 조치 필요 항목', q: '지금 당장 조치가 필요한 보안 이슈는 무엇인가요? 우선순위와 구체적인 조치 방법을 알려주세요.' },
    { icon: '📈', text: '공격 트렌드 분석', q: '최근 공격 트렌드와 패턴을 분석해주세요. 어떤 유형의 공격이 증가하고 있나요?' },
  ];

  document.getElementById('page-content').innerHTML = `
    <div class="grid-2" style="height:calc(100vh - 140px);">
      <!-- 채팅 -->
      <div class="card" style="display:flex;flex-direction:column;height:100%;overflow:hidden;">
        <div class="card-title" style="flex-shrink:0;">
          🤖 AI 보안 분석 채팅
          <div style="margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            ${ctxBadge}
            <button class="btn btn-secondary btn-sm" onclick="newChatSession()">새 세션</button>
          </div>
        </div>

        <!-- DB 연결 상태 배너 -->
        ${total === 0 ? `
        <div style="flex-shrink:0;padding:10px 14px;background:rgba(255,140,0,0.1);border:1px solid rgba(255,140,0,0.3);border-radius:6px;margin-bottom:10px;font-size:12px;color:#ffa500;">
          ⚠️ <strong>분석된 알람 데이터가 없습니다.</strong> 
          Gmail 설정에서 메일 수집 후 LLM 분석을 진행하면 실제 보안 데이터 기반 답변이 가능합니다.
          <button class="btn btn-secondary btn-sm" style="margin-left:8px;" onclick="navigate('gmail-config')">📥 메일 수집 설정</button>
        </div>` : ''}
        
        <div id="chat-messages" style="flex:1;overflow-y:auto;min-height:0;">
          <div class="chat-message assistant">
            <div class="chat-avatar">🤖</div>
            <div class="chat-bubble" style="white-space:pre-wrap;">안녕하세요! 보안 AI 어시스턴트입니다.

현재 <strong>DB의 실제 알람 데이터를 기반</strong>으로 답변합니다.
${total > 0 
  ? `📊 연결된 데이터: 최근 7일 ${total}건 (Critical:${sev.critical||0} / High:${sev.high||0} / Medium:${sev.medium||0})`
  : '⚠️ 아직 수집/분석된 알람이 없습니다.'}

오른쪽의 빠른 질문 버튼을 클릭하거나, 직접 질문을 입력하세요.
            </div>
          </div>
        </div>
        
        <div style="flex-shrink:0;display:flex;gap:8px;margin-top:10px;">
          <select class="form-select" id="chat-model" style="width:140px;">
            <option value="">기본 모델</option>
          </select>
          <select class="form-select" id="chat-days" style="width:80px;" onchange="_chatContextDays=parseInt(this.value)">
            <option value="7" selected>7일</option>
            <option value="30">30일</option>
            <option value="90">90일</option>
          </select>
          <input class="form-input" id="chat-input" placeholder="보안 알람에 대해 질문하세요... (Enter 전송)" 
                 style="flex:1;" onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendChat();}">
          <button class="btn btn-primary" onclick="sendChat()">전송</button>
        </div>
        <div style="flex-shrink:0;font-size:11px;color:var(--text-muted);margin-top:4px;">
          💡 DB의 실제 알람 데이터가 자동으로 AI 컨텍스트에 포함됩니다
        </div>
      </div>
      
      <!-- 빠른 질문 & 세션 -->
      <div style="display:flex;flex-direction:column;gap:16px;height:100%;overflow:hidden;">
        <div class="card" style="flex:1;overflow-y:auto;min-height:0;">
          <div class="card-title">⚡ 빠른 분석 질문</div>
          <div style="display:flex;flex-direction:column;gap:5px;">
            ${quickQuestions.map(({icon, text, q}) => `
              <button class="btn btn-secondary btn-sm" 
                      style="text-align:left;justify-content:flex-start;padding:7px 10px;" 
                      onclick="sendQuickChat(${JSON.stringify(q)})">
                ${icon} ${text}
              </button>`).join('')}
          </div>
        </div>
        
        <div class="card" style="flex:1;overflow-y:auto;min-height:0;">
          <div class="card-title">📚 세션 히스토리</div>
          <div id="session-list">로딩 중...</div>
        </div>
      </div>
    </div>
  `;
  
  loadChatModels();
  loadChatSessions();
}

async function loadChatModels() {
  const data = await api('/api/llm/models');
  const select = document.getElementById('chat-model');
  if (select && data.models) {
    data.models.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m;
      opt.textContent = m;
      select.appendChild(opt);
    });
  }
}

async function loadChatSessions() {
  const data = await api('/api/llm/sessions');
  const container = document.getElementById('session-list');
  if (!container) return;
  
  if (!data.sessions || !data.sessions.length) {
    container.innerHTML = '<div style="color:var(--text-muted);font-size:13px;">이전 세션 없음</div>';
    return;
  }
  
  container.innerHTML = data.sessions.map(s => `
    <div style="padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;cursor:pointer;" 
         onclick="loadSession('${s.session_id}')">
      <div style="font-size:11px;color:var(--text-muted);">${formatDate(s.last_message)} · ${s.message_count}개 메시지</div>
      <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">${escHtml((s.preview||'').slice(0,80))}</div>
    </div>`).join('');
}

function setQuickChat(text) {
  const input = document.getElementById('chat-input');
  if (input) {
    input.value = text;
    input.focus();
  }
}

// 빠른 질문 버튼: 바로 전송
async function sendQuickChat(text) {
  const input = document.getElementById('chat-input');
  if (input) input.value = text;
  await sendChat();
}

async function sendChat() {
  const input = document.getElementById('chat-input');
  const text = input?.value?.trim();
  if (!text) return;
  
  input.value = '';
  
  appendChatMessage('user', text);
  
  const model = document.getElementById('chat-model')?.value || null;
  const days  = parseInt(document.getElementById('chat-days')?.value || _chatContextDays || 7);
  
  // 타이핑 표시
  const typingId = 'typing_' + Date.now();
  appendChatMessage('assistant', '...', typingId);
  
  const result = await api('/api/llm/chat', 'POST', {
    messages: [{ role: 'user', content: text }],
    session_id: chatSessionId,
    model: model || undefined,
    context_days: days,
  });
  
  // 타이핑 제거 후 실제 응답 표시
  const typingEl = document.getElementById(typingId);
  if (typingEl) typingEl.closest('.chat-message').remove();
  
  const response = result.response || '응답을 받지 못했습니다.';
  appendChatMessage('assistant', response);

  // 컨텍스트 정보 표시 (디버그)
  if (result.context_used && result.context_used.total_alerts > 0) {
    const ctx = result.context_used;
    // 기존 컨텍스트 배지 업데이트
    const badge = document.querySelector('.card-title [style*="accent-green"]');
    if (badge) badge.textContent = `📊 DB 연결: ${ctx.total_alerts}건`;
  }
}

// 마크다운 간단 렌더링 (Bold, 목록, 헤더)
function renderMarkdown(text) {
  if (!text) return '';
  return escHtml(text)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/^### (.+)$/gm, '<div style="font-size:14px;font-weight:700;color:var(--text-primary);margin:10px 0 4px;">$1</div>')
    .replace(/^## (.+)$/gm, '<div style="font-size:15px;font-weight:700;color:var(--accent-cyan);margin:12px 0 4px;">$1</div>')
    .replace(/^# (.+)$/gm, '<div style="font-size:16px;font-weight:700;color:var(--accent-blue);margin:12px 0 6px;">$1</div>')
    .replace(/^[-•] (.+)$/gm, '<div style="padding-left:12px;">• $1</div>')
    .replace(/^\d+\. (.+)$/gm, '<div style="padding-left:12px;">$&</div>')
    .replace(/`([^`]+)`/g, '<code style="background:rgba(100,100,200,0.15);padding:1px 5px;border-radius:3px;font-family:monospace;font-size:12px;">$1</code>')
    .replace(/\n\n/g, '<br><br>')
    .replace(/\n/g, '<br>');
}

function appendChatMessage(role, content, id = null) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  
  const div = document.createElement('div');
  div.className = `chat-message ${role}`;
  if (id) div.id = id;

  const bubbleContent = content === '...'
    ? '<div class="spinner" style="width:16px;height:16px;"></div>'
    : (role === 'assistant' ? renderMarkdown(content) : escHtml(content));
  
  div.innerHTML = `
    <div class="chat-avatar">${role === 'user' ? '👤' : '🤖'}</div>
    <div class="chat-bubble" style="line-height:1.7;">${bubbleContent}</div>
  `;
  
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function newChatSession() {
  chatSessionId = 'session_' + Date.now();
  _chatContextAlertIds = [];
  const container = document.getElementById('chat-messages');
  if (container) {
    container.innerHTML = `
      <div class="chat-message assistant">
        <div class="chat-avatar">🤖</div>
        <div class="chat-bubble">새 채팅 세션이 시작되었습니다. DB의 최신 알람 데이터가 자동으로 컨텍스트에 포함됩니다.</div>
      </div>
    `;
  }
  loadChatSessions();
}

async function loadSession(sessionId) {
  chatSessionId = sessionId;
  const data = await api(`/api/llm/chat/history/${sessionId}`);
  
  const container = document.getElementById('chat-messages');
  if (!container) return;
  
  container.innerHTML = '';
  (data.messages || []).forEach(msg => {
    appendChatMessage(msg.role, msg.content);
  });
}

// 알람 상세에서 AI 질의 → 해당 알람을 컨텍스트로 채팅
let _chatContextAlertIds = [];

function openChatWithContext(alertId) {
  _chatContextAlertIds = [alertId];
  navigate('chat');
  setTimeout(async () => {
    // 알람 정보 미리 가져와서 채팅에 주입
    const alert = await api(`/api/alerts/${alertId}`);
    const subject = alert.subject ? `"${alert.subject.slice(0, 50)}"` : `ID:${alertId}`;
    const input = document.getElementById('chat-input');
    if (input) {
      input.value = `알람 ${subject} (ID:${alertId})에 대해 상세 분석해주세요. 위험도 평가와 대응 방안을 알려주세요.`;
      input.focus();
    }
    // 알람 컨텍스트 배지 표시
    const title = document.querySelector('#chat-messages + div');
  }, 600);
}

async function _sendChatWithAlertContext(text, alertIds) {
  const input = document.getElementById('chat-input');
  if (input) input.value = text;

  const model = document.getElementById('chat-model')?.value || null;
  const days  = parseInt(document.getElementById('chat-days')?.value || _chatContextDays || 7);

  appendChatMessage('user', text);
  if (input) input.value = '';

  const typingId = 'typing_' + Date.now();
  appendChatMessage('assistant', '...', typingId);

  const result = await api('/api/llm/chat', 'POST', {
    messages: [{ role: 'user', content: text }],
    session_id: chatSessionId,
    model: model || undefined,
    context_alert_ids: alertIds,
    context_days: days,
  });

  const typingEl = document.getElementById(typingId);
  if (typingEl) typingEl.closest('.chat-message').remove();

  appendChatMessage('assistant', result.response || '응답을 받지 못했습니다.');
  _chatContextAlertIds = [];
}

// ============================================================
// 지식베이스
// ============================================================
async function renderKnowledge() {
  const data = await api('/api/llm/knowledge?limit=50');
  
  const rows = (data.items || []).map(kb => `
    <tr>
      <td><span class="badge badge-info">${kb.category}</span></td>
      <td style="font-size:13px;">${escHtml(kb.title || '')}</td>
      <td style="font-size:12px;color:var(--text-muted);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
        ${escHtml(kb.content || '')}
      </td>
      <td>${(kb.tags || []).map(t => `<span class="badge badge-info">${t}</span>`).join(' ')}</td>
      <td style="color:var(--text-muted);font-size:12px;">${kb.use_count || 0}</td>
      <td style="font-size:11px;color:var(--text-muted);">${formatDate(kb.created_at)}</td>
    </tr>`).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:30px;">지식베이스가 비어있습니다</td></tr>';
  
  document.getElementById('page-content').innerHTML = `
    <div class="card" style="margin-bottom:16px;">
      <div class="card-title">➕ 지식 추가</div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">카테고리</label>
          <select class="form-select" id="kb-category">
            <option value="alert_pattern">알람 패턴</option>
            <option value="false_positive">오탐 패턴</option>
            <option value="recommendation">권고사항</option>
            <option value="threat_intel">위협 인텔리전스</option>
            <option value="manual">수동 입력</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">제목</label>
          <input class="form-input" id="kb-title" placeholder="지식 항목 제목">
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">내용</label>
        <textarea class="form-textarea" id="kb-content" placeholder="AI 학습에 활용할 지식 내용을 입력하세요..."></textarea>
      </div>
      <div class="form-group">
        <label class="form-label">태그 (쉼표로 구분)</label>
        <input class="form-input" id="kb-tags" placeholder="공격,브루트포스,로그인실패">
      </div>
      <button class="btn btn-primary" onclick="addKnowledge()">✅ 지식베이스에 추가</button>
    </div>
    
    <div class="card">
      <div class="card-title">🧠 지식베이스 (${data.items?.length || 0}개 항목)</div>
      <div class="table-container">
        <table>
          <thead><tr><th>카테고리</th><th>제목</th><th>내용</th><th>태그</th><th>활용횟수</th><th>등록일</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `;
}

async function addKnowledge() {
  const category = document.getElementById('kb-category')?.value;
  const title = document.getElementById('kb-title')?.value?.trim();
  const content = document.getElementById('kb-content')?.value?.trim();
  const tagsRaw = document.getElementById('kb-tags')?.value?.trim();
  const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()) : [];
  
  if (!title || !content) { showToast('제목과 내용을 입력해주세요', 'warning'); return; }
  
  const result = await api('/api/llm/knowledge', 'POST', { category, title, content, tags });
  if (result.success) {
    showToast('✅ 지식베이스에 추가되었습니다', 'success');
    renderKnowledge();
  } else {
    showToast('추가 실패: ' + (result.error || ''), 'error');
  }
}

// ============================================================
// Gmail 설정
// ============================================================
async function renderGmailConfig() {
  const status = await api('/api/gmail/status');
  const envData = await api('/api/settings/env');

  // OAuth 모드면 Gmail 레이블도 조회
  let oauthLabels = [];
  if (status.method === 'oauth' && status.connected) {
    const labelsResp = await api('/api/gmail/labels');
    oauthLabels = labelsResp.labels || [];
  }

  const connectedHtml = status.connected
    ? `<div style="color:var(--accent-green);font-size:14px;font-weight:bold;">✅ 연결됨 (${status.method === 'oauth' ? 'OAuth' : 'App Password'}) ${status.user ? `· ${status.user}` : ''}</div>`
    : `<div style="color:var(--critical);font-size:14px;font-weight:bold;">❌ 연결 안됨 — 아래에서 인증하세요</div>`;

  // 수집 설정 탭 — OAuth: 레이블 드롭다운 / App Password: 메일함 텍스트 입력
  const fetchMailboxHtml = status.method === 'oauth' && oauthLabels.length > 0
    ? `<div class="form-group">
        <label class="form-label">수집할 레이블 (Ctrl+클릭으로 다중 선택)</label>
        <select class="form-select" id="fetch-label" multiple style="height:120px;">
          ${oauthLabels.map(l => `<option value="${l.id}">${l.name}</option>`).join('')}
        </select>
      </div>`
    : `<div class="form-group">
        <label class="form-label">수집할 메일함 (IMAP 폴더명)</label>
        <div style="display:flex;gap:8px;align-items:flex-end;">
          <input class="form-input" id="fetch-mailbox" placeholder="INBOX" value="${envData.gmail_mailbox || 'INBOX'}" style="flex:1;">
          <button class="btn btn-secondary" style="white-space:nowrap;" onclick="loadImapMailboxes()">📂 폴더 목록</button>
        </div>
        <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">
          일반: <code>INBOX</code> · 전체보관함: <code>[Gmail]/All Mail</code> · 스팸: <code>[Gmail]/Spam</code>
        </div>
        <div id="imap-mailbox-list" style="margin-top:8px;"></div>
      </div>`;

  document.getElementById('page-content').innerHTML = `
    <div class="card" style="margin-bottom:16px;">
      <div class="card-title">📧 Gmail 연결 상태</div>
      ${connectedHtml}
      <div style="margin-top:6px;font-size:13px;color:var(--text-muted);">${status.message || ''}</div>
    </div>

    <div class="tabs">
      <div class="tab active" onclick="switchTab('gmail-apppass', this)">App Password</div>
      <div class="tab" onclick="switchTab('gmail-oauth', this)">OAuth 인증</div>
      <div class="tab" onclick="switchTab('gmail-fetch', this)">수집 설정</div>
    </div>

    <div id="gmail-apppass" class="tab-content">
      <div class="card">
        <div class="card-title">🔑 App Password 설정</div>
        ${envData.gmail_user && envData.gmail_app_password
          ? `<div style="background:#1a3a2a;border:1px solid var(--accent-green);border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px;">
              ✅ <strong>저장된 계정:</strong> ${envData.gmail_user} &nbsp;·&nbsp; 비밀번호: ****저장됨
            </div>`
          : `<div style="background:#3a1a1a;border:1px solid var(--critical);border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px;">
              ⚠️ 아직 App Password가 설정되지 않았습니다.
            </div>`
        }
        <div style="font-size:13px;color:var(--text-muted);margin-bottom:16px;line-height:1.8;">
          Gmail 계정 → <strong>Google 계정 보안</strong> → <strong>2단계 인증 활성화</strong> →
          <a href="https://myaccount.google.com/apppasswords" target="_blank" style="color:var(--accent-blue);">앱 비밀번호 생성</a>
          (앱: 기타, 이름: SecMail)
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Gmail 계정</label>
            <input class="form-input" id="ap-email" type="email" placeholder="your@gmail.com" value="${envData.gmail_user || ''}">
          </div>
          <div class="form-group">
            <label class="form-label">앱 비밀번호 (16자리, 공백 없이 입력)</label>
            <input class="form-input" id="ap-password" type="password"
              placeholder="${envData.gmail_app_password ? '변경하려면 새 비밀번호 입력' : 'abcdefghijklmnop'}">
          </div>
        </div>
        <button class="btn btn-primary" onclick="saveAppPassword()">💾 저장 및 연결 테스트</button>
      </div>
    </div>

    <div id="gmail-oauth" class="tab-content hidden">
      <div class="card">
        <div class="card-title">🔑 Google OAuth 인증</div>
        <div style="font-size:13px;color:var(--text-muted);margin-bottom:16px;line-height:1.8;">
          1. <a href="https://console.cloud.google.com" target="_blank" style="color:var(--accent-blue);">Google Cloud Console</a>에서 프로젝트 생성<br>
          2. Gmail API 활성화<br>
          3. OAuth 2.0 클라이언트 ID 생성 (데스크톱 앱)<br>
          4. client_secret.json 다운로드하여 아래에 붙여넣기
        </div>
        <div class="form-group">
          <label class="form-label">client_secret.json 내용</label>
          <textarea class="form-textarea" id="oauth-secret" placeholder='{"installed":{"client_id":"...","client_secret":"...",...}}'></textarea>
        </div>
        <button class="btn btn-primary" onclick="initOAuth()">🔐 인증 URL 생성</button>
        <div id="oauth-result" style="margin-top:16px;"></div>
      </div>
    </div>

    <div id="gmail-fetch" class="tab-content hidden">
      <div class="card">
        <div class="card-title">⚙️ 메일 수집 설정</div>
        ${fetchMailboxHtml}
        <div class="form-group">
          <label class="form-label">Gmail 검색 쿼리</label>
          <input class="form-input" id="fetch-query" placeholder="subject:security OR subject:alert OR subject:warning" value="${envData.gmail_query || ''}">
          <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">비워두면 전체 수신함 수집</div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">최대 수집 건수</label>
            <input class="form-input" id="fetch-max" type="number" value="${envData.gmail_max_results || 50}" min="1" max="200">
          </div>
          <div class="form-group">
            <label class="form-label">수집 기준일 (YYYY/MM/DD)</label>
            <input class="form-input" id="fetch-after" placeholder="2024/01/01" value="${envData.gmail_after_date || ''}">
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">자동 수집 주기 (분, 0=비활성)</label>
            <input class="form-input" id="fetch-interval" type="number" value="${envData.fetch_interval_minutes || 0}" min="0" max="1440" step="10"
              placeholder="0">
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">
              ⚡ 10분 이상 설정 시 자동 수집 활성화 · 0 입력 시 매일 09:00 1회만 수집
            </div>
          </div>
          <div class="form-group" style="align-self:flex-end;">
            <div id="scheduler-status-badge" style="font-size:13px;color:var(--text-muted);">스케줄 확인 중...</div>
          </div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-primary" onclick="fetchEmails()">📥 지금 수집</button>
          <button class="btn btn-warning" onclick="analyzeAllPending()">🤖 미분석 전체 분석</button>
          <button class="btn btn-secondary" onclick="saveFetchSettings()">💾 설정 저장</button>
        </div>
      </div>
    </div>
  `;
  // 스케줄러 상태 로드
  loadSchedulerStatus();
}

async function loadSchedulerStatus() {
  const badge = document.getElementById('scheduler-status-badge');
  if (!badge) return;
  const data = await api('/api/settings/scheduler-status');
  if (data.error) { badge.textContent = '스케줄 상태 조회 실패'; return; }
  const interval = data.fetch_interval_minutes || 0;
  const periodicJob = (data.jobs || []).find(j => j.id === 'periodic_fetch');
  if (interval >= 10 && periodicJob) {
    const next = periodicJob.next_run ? new Date(periodicJob.next_run).toLocaleString('ko-KR') : '-';
    badge.innerHTML = `<span style="color:var(--accent-green);">✅ 자동 수집 활성 (${interval}분 간격)</span><br><span style="font-size:11px;color:var(--text-muted);">다음 실행: ${next}</span>`;
  } else {
    badge.innerHTML = `<span style="color:var(--text-muted);">⏸ 자동 수집 비활성 (매일 09:00 1회)</span>`;
  }
}

async function loadImapMailboxes() {
  const listDiv = document.getElementById('imap-mailbox-list');
  if (!listDiv) return;
  listDiv.innerHTML = '<span style="color:var(--text-muted);font-size:13px;">📂 폴더 목록 불러오는 중...</span>';

  const res = await api('/api/gmail/mailboxes');
  if (!res.success && !res.mailboxes?.length) {
    const common = res.common || ['INBOX', '[Gmail]/All Mail', '[Gmail]/Spam', '[Gmail]/Sent Mail'];
    listDiv.innerHTML = `
      <div style="font-size:13px;color:var(--critical);margin-bottom:6px;">⚠️ 폴더 목록 조회 실패 (App Password 설정 후 재시도): ${res.error || ''}</div>
      <div style="font-size:12px;color:var(--text-muted);">자주 쓰는 폴더:</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;">
        ${common.map(m => `<button class="btn btn-secondary" style="font-size:12px;padding:4px 10px;" onclick="document.getElementById('fetch-mailbox').value='${m}'">${m}</button>`).join('')}
      </div>`;
    return;
  }
  const mailboxes = res.mailboxes?.length ? res.mailboxes : (res.common || []);
  listDiv.innerHTML = `
    <div style="font-size:12px;color:var(--text-muted);margin-bottom:6px;">클릭하면 선택됩니다:</div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;">
      ${mailboxes.map(m => `<button class="btn btn-secondary" style="font-size:12px;padding:4px 10px;" onclick="document.getElementById('fetch-mailbox').value='${m}'">${m}</button>`).join('')}
    </div>`;
}

function switchTab(contentId, tabEl) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.add('hidden'));
  tabEl.classList.add('active');
  document.getElementById(contentId)?.classList.remove('hidden');
}

async function initOAuth() {
  const secret = document.getElementById('oauth-secret')?.value?.trim();
  if (!secret) { showToast('client_secret.json을 입력해주세요', 'warning'); return; }
  
  const result = await api('/api/gmail/oauth/init', 'POST', { client_secret_json: secret });
  const resultDiv = document.getElementById('oauth-result');
  
  if (result.success) {
    resultDiv.innerHTML = `
      <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:16px;">
        <p style="color:var(--accent-green);font-weight:600;margin-bottom:12px;">✅ 인증 URL 생성됨</p>
        <p style="font-size:13px;color:var(--text-muted);margin-bottom:12px;">${result.message}</p>
        <a href="${result.auth_url}" target="_blank" class="btn btn-primary" style="margin-bottom:16px;">🔗 Google 인증 페이지 열기</a>
        <div class="form-group" style="margin-top:12px;">
          <label class="form-label">인증 코드 입력</label>
          <input class="form-input" id="oauth-code" placeholder="Google에서 받은 인증 코드">
        </div>
        <button class="btn btn-success" onclick="completeOAuth('${btoa(secret)}')">✅ 인증 완료</button>
      </div>
    `;
  } else {
    resultDiv.innerHTML = `<div style="color:var(--critical);">오류: ${result.error}</div>`;
  }
}

async function completeOAuth(secretB64) {
  const code = document.getElementById('oauth-code')?.value?.trim();
  if (!code) { showToast('인증 코드를 입력해주세요', 'warning'); return; }
  
  const secret = atob(secretB64);
  const result = await api('/api/gmail/oauth/complete', 'POST', {
    client_secret_json: secret,
    auth_code: code
  });
  
  if (result.success) {
    showToast('✅ Gmail 인증 완료!', 'success');
    renderGmailConfig();
  } else {
    showToast('인증 실패: ' + result.error, 'error');
  }
}

async function saveAppPassword() {
  const email = document.getElementById('ap-email')?.value?.trim();
  const password = document.getElementById('ap-password')?.value?.trim();

  if (!email) {
    showToast('Gmail 계정 이메일을 입력해주세요.', 'error');
    return;
  }
  if (!password) {
    showToast('앱 비밀번호를 입력해주세요. (공백 없이 16자리)', 'error');
    return;
  }

  // 앱 비밀번호 공백 제거 (Google이 보여주는 형식: "abcd efgh ijkl mnop")
  const cleanPassword = password.replace(/\s/g, '');
  if (cleanPassword.length < 8) {
    showToast('앱 비밀번호가 너무 짧습니다. 16자리를 입력해주세요.', 'error');
    return;
  }

  showToast('🔄 IMAP 연결 테스트 중...', 'info');

  const result = await api('/api/gmail/app-password/save', 'POST', {
    gmail_user: email,
    gmail_app_password: cleanPassword,
  });

  if (result.success) {
    showToast('✅ App Password 저장 완료! ' + (result.message || ''), 'success');
    setTimeout(() => renderGmailConfig(), 800);
  } else {
    const errMsg = result.error || result.message || '저장 실패';
    showToast('❌ ' + errMsg, 'error');
    // 실패해도 이메일은 화면에 유지
  }
}

async function saveFetchSettings() {
  const query = document.getElementById('fetch-query')?.value?.trim();
  const maxResults = document.getElementById('fetch-max')?.value?.trim();
  const afterDate = document.getElementById('fetch-after')?.value?.trim();
  const intervalVal = document.getElementById('fetch-interval')?.value?.trim();
  // IMAP 모드: text input / OAuth 모드: select (multiple)
  const mailboxInput = document.getElementById('fetch-mailbox');
  const labelSelect = document.getElementById('fetch-label');

  const payload = {};
  if (query !== undefined) payload.gmail_query = query;
  if (maxResults) payload.gmail_max_results = maxResults;
  if (afterDate !== undefined) payload.gmail_after_date = afterDate;
  if (intervalVal !== undefined) payload.fetch_interval_minutes = intervalVal;

  if (mailboxInput) {
    const mailbox = mailboxInput.value.trim();
    if (mailbox) payload.gmail_mailbox = mailbox;
  } else if (labelSelect) {
    const selectedLabels = Array.from(labelSelect.selectedOptions).map(o => o.value);
    payload.gmail_label_ids = selectedLabels;
  }

  const result = await api('/api/settings/env', 'POST', payload);
  if (result.success) {
    showToast('✅ 수집 설정 저장 완료', 'success');
    // 스케줄러 상태 갱신
    setTimeout(() => loadSchedulerStatus(), 500);
  } else {
    showToast('❌ 저장 실패: ' + (result.detail || result.message || ''), 'error');
  }
}

// ============================================================
// 리포트 발송
// ============================================================
async function renderReports() {
  const reports = await api('/api/settings/reports');
  const envData = await api('/api/settings/env');
  
  const reportRows = (reports.reports || []).map(r => `
    <tr>
      <td style="font-size:12px;">${formatDate(r.created_at)}</td>
      <td><span class="badge badge-info">${r.report_type}</span></td>
      <td style="font-size:12px;color:var(--text-muted);">${r.period_start ? r.period_start.slice(0,10) : ''} ~ ${r.period_end ? r.period_end.slice(0,10) : ''}</td>
      <td style="font-size:12px;">${(r.recipients || []).join(', ')}</td>
      <td>${r.total_alerts || 0}</td>
      <td><span class="badge ${r.status === 'sent' ? 'badge-analyzed' : 'badge-critical'}">${r.status}</span></td>
    </tr>`).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:20px;">발송 이력 없음</td></tr>';
  
  document.getElementById('page-content').innerHTML = `
    <div class="grid-2">
      <div class="card">
        <div class="card-title">📨 리포트 즉시 발송</div>
        <div class="form-group">
          <label class="form-label">수신자 이메일 (쉼표로 구분)</label>
          <input class="form-input" id="report-recipients" placeholder="admin@company.com, security@company.com" 
                 value="${(envData.report_recipients || []).join(', ')}">
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">리포트 유형</label>
            <select class="form-select" id="report-type">
              <option value="manual">수동 발송</option>
              <option value="daily">일일 리포트</option>
              <option value="weekly">주간 리포트</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">기간 (일)</label>
            <select class="form-select" id="report-days">
              <option value="1">오늘 (1일)</option>
              <option value="7">7일</option>
              <option value="30">30일</option>
            </select>
          </div>
        </div>
        <button class="btn btn-primary" onclick="sendReport()">📧 리포트 발송</button>
        
        <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border);">
          <div class="card-title">🔧 SMTP 설정</div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">SMTP 호스트</label>
              <input class="form-input" id="smtp-host" value="${envData.smtp_host || 'smtp.gmail.com'}">
            </div>
            <div class="form-group">
              <label class="form-label">SMTP 포트</label>
              <input class="form-input" id="smtp-port" type="number" value="${envData.smtp_port || 587}">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">SMTP 사용자</label>
              <input class="form-input" id="smtp-user" value="${envData.smtp_user || ''}">
            </div>
            <div class="form-group">
              <label class="form-label">SMTP 비밀번호</label>
              <input class="form-input" id="smtp-pass" type="password" placeholder="앱 비밀번호">
            </div>
          </div>
          <button class="btn btn-secondary" onclick="saveReportSettings()">💾 SMTP 설정 저장</button>
        </div>
      </div>
      
      <div class="card">
        <div class="card-title">⏰ 자동 발송 스케줄</div>
        <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:16px;">
          <div style="font-size:13px;color:var(--text-secondary);line-height:2;">
            <div>📅 <strong>매일 09:00</strong> - 메일 자동 수집 및 분석</div>
            <div>📧 <strong>매일 09:30</strong> - 일일 보안 리포트 자동 발송</div>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">자동 발송 수신자</label>
          <input class="form-input" id="auto-recipients" placeholder="admin@company.com" 
                 value="${(envData.report_recipients || []).join(', ')}">
        </div>
        <button class="btn btn-secondary" onclick="saveAutoSettings()">💾 자동 발송 설정 저장</button>
      </div>
    </div>
    
    <div class="card">
      <div class="card-title">📋 발송 이력</div>
      <div class="table-container">
        <table>
          <thead><tr><th>발송시간</th><th>유형</th><th>기간</th><th>수신자</th><th>알람수</th><th>상태</th></tr></thead>
          <tbody>${reportRows}</tbody>
        </table>
      </div>
    </div>
  `;
}

async function sendReport() {
  const recipientsRaw = document.getElementById('report-recipients')?.value || '';
  const recipients = recipientsRaw.split(',').map(r => r.trim()).filter(r => r);
  const reportType = document.getElementById('report-type')?.value || 'manual';
  const days = parseInt(document.getElementById('report-days')?.value || 1);
  
  if (!recipients.length) { showToast('수신자 이메일을 입력해주세요', 'warning'); return; }
  
  showToast('📧 리포트 생성 및 발송 중...', 'info');
  
  const result = await api('/api/settings/report/send', 'POST', {
    recipients,
    report_type: reportType,
    days,
  });
  
  if (result.success) {
    showToast('✅ 리포트 발송 완료!', 'success');
    renderReports();
  } else {
    showToast('발송 실패: ' + (result.send_result?.error || result.error || ''), 'error');
  }
}

async function saveReportSettings() {
  const result = await api('/api/settings/env', 'POST', {
    smtp_host: document.getElementById('smtp-host')?.value,
    smtp_port: parseInt(document.getElementById('smtp-port')?.value || 587),
    smtp_user: document.getElementById('smtp-user')?.value,
    smtp_password: document.getElementById('smtp-pass')?.value,
  });
  if (result.success) showToast('✅ SMTP 설정 저장 완료', 'success');
}

async function saveAutoSettings() {
  const recipientsRaw = document.getElementById('auto-recipients')?.value || '';
  const recipients = recipientsRaw.split(',').map(r => r.trim()).filter(r => r);
  const result = await api('/api/settings/env', 'POST', { report_recipients: recipients });
  if (result.success) showToast('✅ 자동 발송 설정 저장 완료', 'success');
}

// ============================================================
// 환경 설정
// ============================================================
async function renderSettings() {
  const envData = await api('/api/settings/env');
  const llmStatus = await api('/api/llm/status');
  const llmModels = await api('/api/llm/models');
  const sysInfo = await api('/api/settings/system-info');
  
  const modelOptions = (llmModels.models || []).map(m => `<option value="${m}" ${m.includes('gemma3') ? 'selected' : ''}>${m}</option>`).join('');
  const currentModel = envData.ollama_model || 'gemma3:4b';
  
  document.getElementById('page-content').innerHTML = `
    <!-- 시스템 현황 -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-title">🖥️ 시스템 현황</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;">
        <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:12px;">
          <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">🤖 LLM 모델</div>
          <div style="font-size:13px;font-weight:600;color:var(--accent-cyan);">${sysInfo.ollama_model || currentModel}</div>
          <div style="font-size:10px;color:${llmStatus.connected ? 'var(--accent-green)' : 'var(--critical)'};">${llmStatus.connected ? '● 연결됨' : '● 연결 안됨'}</div>
        </div>
        <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:12px;">
          <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">🗄️ 데이터베이스</div>
          <div style="font-size:13px;font-weight:600;color:var(--accent-blue);">${sysInfo.db_type || 'SQLite'}</div>
          <div style="font-size:10px;color:var(--text-muted);">${sysInfo.db_host || 'local'}</div>
        </div>
        <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:12px;">
          <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">🖥️ GPU</div>
          <div style="font-size:12px;font-weight:600;color:var(--accent-green);">${(sysInfo.gpu || 'N/A').split(',')[0]}</div>
        </div>
        <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:12px;">
          <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">🌐 서비스 포트</div>
          <div style="font-size:13px;font-weight:600;color:var(--accent-yellow);">Frontend: ${sysInfo.frontend_port || 61001}</div>
          <div style="font-size:10px;color:var(--text-muted);">API: ${sysInfo.api_port || 8000}</div>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <!-- LLM 설정 -->
      <div class="card">
        <div class="card-title">🤖 로컬 LLM (Gemma4/Ollama) 설정</div>
        <div style="margin-bottom:12px;padding:10px;border-radius:6px;background:${llmStatus.connected ? 'rgba(6,214,160,0.1)' : 'rgba(239,35,60,0.1)'};border:1px solid ${llmStatus.connected ? 'rgba(6,214,160,0.3)' : 'rgba(239,35,60,0.3)'};">
          <div style="color:${llmStatus.connected ? 'var(--accent-green)' : 'var(--critical)'};">
            ${llmStatus.connected ? '✅ Ollama 연결됨' : '❌ Ollama 연결 안됨'}
          </div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">${llmStatus.message || llmStatus.error || ''}</div>
        </div>
        <div class="form-group">
          <label class="form-label">Ollama URL</label>
          <input class="form-input" id="llm-url" value="${envData.ollama_url || 'http://localhost:11434'}">
        </div>
        <div class="form-group">
          <label class="form-label">기본 모델 (권장: gemma3:4b)</label>
          <select class="form-select" id="llm-model">
            <option value="gemma3:4b" ${currentModel === 'gemma3:4b' ? 'selected' : ''}>gemma3:4b ⭐ (NVIDIA GB10 최적화)</option>
            <option value="gemma3:12b" ${currentModel === 'gemma3:12b' ? 'selected' : ''}>gemma3:12b (고성능)</option>
            <option value="llama3.2:3b" ${currentModel === 'llama3.2:3b' ? 'selected' : ''}>llama3.2:3b (소형)</option>
            <option value="llama3.1:8b" ${currentModel === 'llama3.1:8b' ? 'selected' : ''}>llama3.1:8b</option>
            <option value="qwen2.5:7b" ${currentModel === 'qwen2.5:7b' ? 'selected' : ''}>qwen2.5:7b (한국어 우수)</option>
            ${modelOptions}
          </select>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-primary" onclick="saveLLMSettings()">💾 LLM 설정 저장</button>
          <button class="btn btn-secondary" onclick="showModelPull()">📥 모델 다운로드</button>
          <button class="btn btn-secondary" onclick="testLLM()">🔌 연결 테스트</button>
        </div>
      </div>
      
      <!-- API 키 설정 -->
      <div class="card">
        <div class="card-title">🔑 외부 API 키</div>
        <div class="form-group">
          <label class="form-label">AbuseIPDB API Key</label>
          <input class="form-input" id="abuseipdb-key" type="password" 
                 placeholder="${envData.abuseipdb_api_key ? '설정됨 (변경시 입력)' : 'AbuseIPDB API Key'}">
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
            <a href="https://www.abuseipdb.com/api" target="_blank" style="color:var(--accent-blue);">API Key 발급</a> (무료 1000건/일)
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">IPInfo Token</label>
          <input class="form-input" id="ipinfo-token" type="password"
                 placeholder="${envData.ipinfo_token ? '설정됨 (변경시 입력)' : 'IPInfo API Token'}">
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
            <a href="https://ipinfo.io/signup" target="_blank" style="color:var(--accent-blue);">토큰 발급</a> (무료 50,000건/월)
          </div>
        </div>
        <button class="btn btn-primary" onclick="saveAPIKeys()">💾 API Key 저장</button>
      </div>
    </div>
    
    <!-- 모델 다운로드 섹션 -->
    <div id="model-pull-section" class="card hidden">
      <div class="card-title">📥 Ollama 모델 다운로드</div>
      <div style="font-size:13px;color:var(--text-muted);margin-bottom:12px;">
        NVIDIA GB10 GPU로 가속됩니다. 🌟 권장: gemma3:4b (Google Gemma4 - 분석 최적화)
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:12px;">
        ${['gemma3:4b', 'gemma3:12b', 'llama3.2:3b', 'qwen2.5:7b'].map(m => 
          `<button class="btn btn-secondary btn-sm" onclick="document.getElementById('pull-model-name').value='${m}'">📌 ${m}</button>`
        ).join('')}
      </div>
      <div style="display:flex;gap:8px;margin-bottom:12px;">
        <input class="form-input" id="pull-model-name" placeholder="모델명 (예: gemma3:4b)" value="gemma3:4b">
        <button class="btn btn-primary" onclick="pullModel()">📥 다운로드</button>
      </div>
      <div id="pull-progress" style="display:none;">
        <div class="progress-bar" style="margin-bottom:8px;">
          <div class="progress-fill" id="pull-bar" style="width:0%"></div>
        </div>
        <div id="pull-status" style="font-size:12px;color:var(--text-muted);"></div>
      </div>
    </div>

    <!-- 시간대 및 스케줄 설정 -->
    <div class="card">
      <div class="card-title">🕐 시간대 및 업무시간 설정</div>

      <!-- 시간대 정보 패널 -->
      <div style="background:rgba(67,97,238,0.08);border:1px solid rgba(67,97,238,0.3);border-radius:8px;padding:12px 14px;margin-bottom:16px;">
        <div style="font-size:12px;font-weight:600;color:var(--accent-blue);margin-bottom:8px;">ℹ️ 시간대 동작 방식</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px;color:var(--text-secondary);">
          <div>
            <div style="color:var(--text-muted);margin-bottom:3px;">📦 DB 저장 방식</div>
            <div style="font-weight:600;color:var(--accent-cyan);">UTC (협정세계시) 기준 저장</div>
            <div style="font-size:11px;margin-top:2px;">수집된 이메일 날짜를 UTC로 통일 저장</div>
          </div>
          <div>
            <div style="color:var(--text-muted);margin-bottom:3px;">🖥️ 화면 표시 방식</div>
            <div style="font-weight:600;color:var(--accent-green);">설정된 시간대로 자동 변환 표시</div>
            <div style="font-size:11px;margin-top:2px;">UTC → 설정 시간대로 변환하여 표시</div>
          </div>
          <div>
            <div style="color:var(--text-muted);margin-bottom:3px;">🌙 야간/시간외 판단</div>
            <div style="font-weight:600;color:var(--accent-yellow);">설정 시간대 기준으로 판단</div>
            <div style="font-size:11px;margin-top:2px;">업무시간 외 알람에 🌙 표시</div>
          </div>
          <div>
            <div style="color:var(--text-muted);margin-bottom:3px;">⏰ 현재 시각</div>
            <div id="tz-live-clock" style="font-weight:600;color:var(--accent-cyan);font-family:monospace;">--:--:--</div>
            <div style="font-size:11px;margin-top:2px;">현재 적용 시간대: <strong>${envData.app_timezone || 'Asia/Seoul'}</strong></div>
          </div>
        </div>
      </div>

      <div style="font-size:13px;color:var(--text-muted);margin-bottom:14px;">
        시간대 설정은 <strong>알람 수신시간 표시</strong>, <strong>야간 업무외 판단</strong>, <strong>자동 수집·리포트 스케줄</strong>에 모두 적용됩니다.
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">표시 시간대 (IANA timezone)</label>
          <select class="form-select" id="app-timezone" onchange="updateTzPreview()">
            ${[
              'Asia/Seoul', 'Asia/Tokyo', 'Asia/Singapore', 'Asia/Shanghai',
              'Asia/Bangkok', 'Asia/Kolkata', 'Europe/London', 'Europe/Berlin',
              'Europe/Paris', 'America/New_York', 'America/Chicago',
              'America/Los_Angeles', 'America/Sao_Paulo', 'UTC'
            ].map(tz => `<option value="${tz}" ${envData.app_timezone === tz ? 'selected' : ''}>${tz}</option>`).join('')}
          </select>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">현재 적용: <strong style="color:var(--accent-cyan);">${envData.app_timezone || 'Asia/Seoul'}</strong></div>
        </div>
        <div class="form-group">
          <label class="form-label">업무 시작 시간 (0~23시)</label>
          <input class="form-input" id="biz-start" type="number" min="0" max="23" value="${envData.business_start_hour ?? 9}" oninput="updateBizHoursPreview()">
        </div>
        <div class="form-group">
          <label class="form-label">업무 종료 시간 (0~23시)</label>
          <input class="form-input" id="biz-end" type="number" min="0" max="23" value="${envData.business_end_hour ?? 18}" oninput="updateBizHoursPreview()">
        </div>
      </div>

      <!-- 야간 대응 미리보기 -->
      <div id="biz-hours-preview" style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:12px;">
        <div style="font-weight:600;color:var(--text-muted);margin-bottom:6px;">🌙 야간/시간외 판단 기준 미리보기</div>
        <div id="biz-hours-detail" style="color:var(--text-secondary);line-height:1.8;"></div>
      </div>

      <div class="form-row" style="margin-top:8px;">
        <div class="form-group">
          <label class="form-label">일일 수집 시각 (시)</label>
          <input class="form-input" id="fetch-hour" type="number" min="0" max="23" value="${envData.daily_fetch_hour ?? 9}">
        </div>
        <div class="form-group">
          <label class="form-label">일일 수집 시각 (분)</label>
          <input class="form-input" id="fetch-minute" type="number" min="0" max="59" value="${envData.daily_fetch_minute ?? 0}">
        </div>
        <div class="form-group">
          <label class="form-label">일일 리포트 시각 (시)</label>
          <input class="form-input" id="report-hour" type="number" min="0" max="23" value="${envData.daily_report_hour ?? 9}">
        </div>
        <div class="form-group">
          <label class="form-label">일일 리포트 시각 (분)</label>
          <input class="form-input" id="report-minute" type="number" min="0" max="59" value="${envData.daily_report_minute ?? 30}">
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;align-items:center;">
        <button class="btn btn-primary" onclick="saveTimezoneSettings()">💾 시간대 설정 저장</button>
        <div id="tz-scheduler-status" style="font-size:13px;color:var(--text-muted);"></div>
      </div>
    </div>
  `;

  // 라이브 시계 시작 및 업무시간 미리보기 초기화
  _startTzClock();
  updateBizHoursPreview();
}

async function saveLLMSettings() {
  const result = await api('/api/settings/env', 'POST', {
    ollama_url: document.getElementById('llm-url')?.value,
    ollama_model: document.getElementById('llm-model')?.value,
  });
  if (result.success) showToast('✅ LLM 설정 저장 완료', 'success');
}

async function saveTimezoneSettings() {
  const tz       = document.getElementById('app-timezone')?.value;
  const bizStart = document.getElementById('biz-start')?.value;
  const bizEnd   = document.getElementById('biz-end')?.value;
  const fetchH   = document.getElementById('fetch-hour')?.value;
  const fetchM   = document.getElementById('fetch-minute')?.value;
  const reportH  = document.getElementById('report-hour')?.value;
  const reportM  = document.getElementById('report-minute')?.value;

  const payload = {};
  if (tz)       payload.app_timezone        = tz;
  if (bizStart) payload.business_start_hour = bizStart;
  if (bizEnd)   payload.business_end_hour   = bizEnd;
  if (fetchH)   payload.daily_fetch_hour    = fetchH;
  if (fetchM !== undefined) payload.daily_fetch_minute  = fetchM;
  if (reportH)  payload.daily_report_hour   = reportH;
  if (reportM !== undefined) payload.daily_report_minute = reportM;

  const result = await api('/api/settings/env', 'POST', payload);
  if (result.success) {
    // 프론트엔드 시간대 즉시 갱신
    if (tz) _appTimezone = tz;
    if (bizStart) _businessStartHour = parseInt(bizStart);
    if (bizEnd)   _businessEndHour   = parseInt(bizEnd);
    showToast('✅ 시간대 설정 저장 완료 (스케줄 자동 재적용)', 'success');
    // 스케줄러 상태 갱신
    setTimeout(async () => {
      const schedData = await api('/api/settings/scheduler-status');
      const tzDiv = document.getElementById('tz-scheduler-status');
      if (tzDiv && schedData.jobs) {
        const jobList = schedData.jobs.map(j =>
          `<div>📅 ${j.name}: ${j.next_run ? new Date(j.next_run).toLocaleString('ko-KR', {timeZone: _appTimezone}) : '-'}</div>`
        ).join('');
        tzDiv.innerHTML = `<div style="font-size:12px;line-height:1.8;">${jobList}</div>`;
      }
    }, 800);
  } else {
    showToast('❌ 저장 실패: ' + (result.detail || result.message || ''), 'error');
  }
}

// ============================================================
// 시간대 설정 헬퍼
// ============================================================
function _startTzClock() {
  // 기존 타이머 제거
  if (_tzClockTimer) clearInterval(_tzClockTimer);
  function _tick() {
    const el = document.getElementById('tz-live-clock');
    if (!el) { clearInterval(_tzClockTimer); _tzClockTimer = null; return; }
    const tz = document.getElementById('app-timezone')?.value || _appTimezone;
    el.textContent = new Date().toLocaleTimeString('ko-KR', { timeZone: tz, hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }
  _tick();
  _tzClockTimer = setInterval(_tick, 1000);
}

function updateTzPreview() {
  // 시간대 변경 시 라이브 시계 갱신 (타이머는 이미 실행 중)
  updateBizHoursPreview();
}

function updateBizHoursPreview() {
  const el = document.getElementById('biz-hours-detail');
  if (!el) return;
  const tz = document.getElementById('app-timezone')?.value || _appTimezone;
  const startH = parseInt(document.getElementById('biz-start')?.value ?? 9);
  const endH   = parseInt(document.getElementById('biz-end')?.value ?? 18);
  if (isNaN(startH) || isNaN(endH)) return;

  const now = new Date();
  const nowLocal = new Date(now.toLocaleString('en-US', { timeZone: tz }));
  const curHour = nowLocal.getHours();
  const curMin  = nowLocal.getMinutes();
  const weekday = nowLocal.getDay(); // 0=일, 1=월 ... 6=토
  const isWeekend = weekday === 0 || weekday === 6;
  const isOutside = !(startH <= curHour && curHour < endH);
  const isAfterHours = isWeekend || isOutside;

  const dayNames = ['일','월','화','수','목','금','토'];
  const currentTimeStr = `${String(curHour).padStart(2,'0')}:${String(curMin).padStart(2,'0')} (${dayNames[weekday]}요일)`;

  el.innerHTML = `
    <div style="display:flex;gap:16px;flex-wrap:wrap;">
      <div>
        <span style="color:var(--accent-green);">✅ 업무시간</span>: 
        <strong>${String(startH).padStart(2,'0')}:00 ~ ${String(endH).padStart(2,'0')}:00</strong> (평일, ${tz})
      </div>
      <div>
        <span style="color:var(--high);">🌙 야간/시간외</span>: 
        <strong>${String(endH).padStart(2,'0')}:00 ~ ${String(startH).padStart(2,'0')}:00 (다음날)</strong> + 주말
      </div>
    </div>
    <div style="margin-top:6px;">
      현재 ${tz} 시각: <strong style="color:var(--accent-cyan);">${currentTimeStr}</strong>
      → 
      ${isAfterHours
        ? `<span style="color:#ffa500;font-weight:600;">🌙 야간/시간외</span>${isWeekend ? ' (주말)' : ' (업무시간 외)'} — 이 시각 발생 알람은 <span style="background:rgba(255,140,0,0.2);color:#ffa500;padding:1px 5px;border-radius:4px;font-size:11px;">🌙야간</span> 태그가 붙습니다`
        : `<span style="color:var(--accent-green);font-weight:600;">✅ 업무시간 내</span> — 이 시각 발생 알람은 정상 처리됩니다`
      }
    </div>`;
}

async function saveAPIKeys() {
  const abuseKey = document.getElementById('abuseipdb-key')?.value;
  const ipinfoToken = document.getElementById('ipinfo-token')?.value;
  
  const payload = {};
  if (abuseKey) payload.abuseipdb_api_key = abuseKey;
  if (ipinfoToken) payload.ipinfo_token = ipinfoToken;
  
  const result = await api('/api/settings/env', 'POST', payload);
  if (result.success) showToast('✅ API Key 저장 완료', 'success');
}

async function testLLM() {
  showToast('🔌 LLM 연결 테스트 중...', 'info');
  const status = await api('/api/llm/status');
  if (status.connected) {
    showToast(`✅ LLM 연결 성공! 모델 ${status.models?.length || 0}개`, 'success');
  } else {
    showToast('❌ LLM 연결 실패: ' + status.error, 'error');
  }
}

function showModelPull() {
  document.getElementById('model-pull-section')?.classList.toggle('hidden');
}

async function pullModel() {
  const modelName = document.getElementById('pull-model-name')?.value?.trim();
  if (!modelName) { showToast('모델명을 입력해주세요', 'warning'); return; }
  
  const progress = document.getElementById('pull-progress');
  if (progress) progress.style.display = 'block';
  
  try {
    const response = await fetch('/api/llm/pull', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: modelName }),
    });
    
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      
      const text = decoder.decode(value);
      const lines = text.split('\n').filter(l => l.startsWith('data: '));
      
      for (const line of lines) {
        const data = JSON.parse(line.slice(6));
        const statusEl = document.getElementById('pull-status');
        const barEl = document.getElementById('pull-bar');
        
        if (statusEl) statusEl.textContent = data.status || '';
        
        if (data.total && barEl) {
          const pct = Math.round((data.completed || 0) / data.total * 100);
          barEl.style.width = pct + '%';
        }
        
        if (data.status === 'complete') {
          showToast(`✅ ${modelName} 다운로드 완료!`, 'success');
        }
      }
    }
  } catch(e) {
    showToast('다운로드 오류: ' + e.message, 'error');
  }
}

// ============================================================
// 메일 수집
// ============================================================
async function analyzeAllPending() {
  showToast('🤖 미분석 알람 전체 분석 시작...', 'info');
  const result = await api('/api/settings/analyze-pending', 'POST', { limit: 200 });
  if (result.success) {
    showToast(`🤖 ${result.queued}개 알람 분석 진행 중 (백그라운드)`, 'success');
  } else {
    showToast('❌ 분석 실패: ' + (result.detail || result.message || ''), 'error');
  }
}

function resetAlertFilters() {
  _alertFilter.severity = '';
  _alertFilter.status   = '';
  _alertFilter.fp       = '';
  _alertFilter.search   = '';
  _alertFilter.days     = '30';
  // DOM 반영
  const s = document.getElementById('filter-severity');
  const st = document.getElementById('filter-status');
  const fp = document.getElementById('filter-fp');
  const sr = document.getElementById('filter-search');
  const dy = document.getElementById('filter-days');
  if (s)  s.value  = '';
  if (st) st.value = '';
  if (fp) fp.value = '';
  if (sr) sr.value = '';
  if (dy) dy.value = '30';
  renderAlerts(1);
}

// ============================================================
// 상관분석 (2차 침해·횡전개 분석)
// ============================================================
function showCorrelationModal() {
  openModal(`
    <div class="modal-header">
      <div class="modal-title">🕸 보안 알람 상관분석</div>
      <button class="modal-close" onclick="closeModal()">×</button>
    </div>

    <!-- 사용 방법 안내 -->
    <div style="background:rgba(6,214,160,0.06);border:1px solid rgba(6,214,160,0.2);border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:12px;color:var(--text-secondary);">
      <div style="font-weight:600;color:var(--accent-green);margin-bottom:6px;">📖 상관분석 사용 방법</div>
      <ol style="margin:0 0 0 16px;line-height:2;">
        <li><strong>분석 기간</strong>과 <strong>분석 대상</strong>을 선택하세요</li>
        <li><strong>🔍 상관분석 시작</strong> 버튼을 클릭하세요</li>
        <li>LLM이 알람 패턴을 분석합니다 (보통 1~3분 소요)</li>
        <li>분석 중에도 모달을 닫고 다른 작업이 가능합니다<br>
          <span style="color:var(--accent-cyan);">→ 알람 목록 상단의 상태바에서 진행 상태와 결과 요약을 확인할 수 있습니다</span></li>
      </ol>
    </div>

    ${_corrStatus.running ? \`
    <div style="padding:10px 14px;background:rgba(67,97,238,0.1);border:1px solid rgba(67,97,238,0.3);border-radius:8px;margin-bottom:14px;display:flex;align-items:center;gap:10px;">
      <div class="spinner" style="width:16px;height:16px;border-width:2px;"></div>
      <span style="color:var(--accent-cyan);font-weight:600;">상관분석이 진행 중입니다. 잠시 기다려주세요...</span>
    </div>\` : ''}

    <div class="form-row">
      <div class="form-group">
        <label class="form-label">분석 기간</label>
        <select class="form-select" id="corr-days" ${_corrStatus.running ? 'disabled' : ''}>
          <option value="1">오늘 (1일)</option>
          <option value="3">최근 3일</option>
          <option value="7" selected>최근 7일</option>
          <option value="30">최근 30일</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">분석 대상</label>
        <select class="form-select" id="corr-target" ${_corrStatus.running ? 'disabled' : ''}>
          <option value="analyzed">분석완료 알람만</option>
          <option value="all">전체 알람</option>
        </select>
      </div>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:16px;align-items:center;">
      <button class="btn btn-primary" onclick="runCorrelation()" ${_corrStatus.running ? 'disabled' : ''}>
        ${_corrStatus.running ? '⏳ 분석 중...' : '🔍 상관분석 시작'}
      </button>
      <span style="font-size:12px;color:var(--text-muted);">LLM 분석이므로 1~3분 소요됩니다</span>
    </div>
    <div id="corr-result"></div>
  `);
}

async function runCorrelation() {
  const days = parseInt(document.getElementById('corr-days')?.value || 7);
  const target = document.getElementById('corr-target')?.value || 'analyzed';
  const resultDiv = document.getElementById('corr-result');
  if (!resultDiv) return;

  // 전역 상태: 진행 중으로 설정 (알람 목록 페이지 상태바 업데이트)
  _corrStatus = { running: true, lastResult: null };
  _updateCorrStatusBar();

  // 진행 상황 UI: 단계별 애니메이션
  const steps = ['📊 알람 수집 중...', '🔍 IP/패턴 분석 중...', '🤖 AI 상관관계 추론 중...', '📋 결과 정리 중...'];
  let stepIdx = 0;
  resultDiv.innerHTML = `
    <div style="padding:20px;background:var(--bg-primary);border-radius:10px;border:1px solid var(--border);">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
        <div class="spinner" style="width:24px;height:24px;border-width:3px;"></div>
        <div>
          <div id="corr-step-label" style="font-size:14px;font-weight:600;color:var(--text-primary);">${steps[0]}</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">LLM 분석이므로 1~2분 소요됩니다</div>
        </div>
      </div>
      <div class="progress-bar" style="height:6px;margin-bottom:12px;">
        <div class="progress-fill" id="corr-progress-bar" style="width:5%;transition:width 0.5s ease;"></div>
      </div>
      <div id="corr-step-detail" style="font-size:12px;color:var(--text-muted);line-height:1.6;">
        ${steps.map((s,i) => `<div id="corr-s${i}" style="color:${i===0?'var(--accent-cyan)':'var(--text-muted)'}">
          ${i===0?'🔄':'⏳'} ${s}</div>`).join('')}
      </div>
    </div>`;

  if (_corrPollingTimer) clearInterval(_corrPollingTimer);
  let pct = 5;
  _corrPollingTimer = setInterval(() => {
    stepIdx = Math.min(stepIdx + 1, steps.length - 1);
    pct = Math.min(pct + 20, 90);
    const label = document.getElementById('corr-step-label');
    const bar = document.getElementById('corr-progress-bar');
    if (label) label.textContent = steps[stepIdx];
    if (bar) bar.style.width = pct + '%';
    // 이전 단계 완료 표시
    for (let i = 0; i < steps.length; i++) {
      const el = document.getElementById(`corr-s${i}`);
      if (!el) continue;
      if (i < stepIdx) el.style.color = 'var(--accent-green)';
      else if (i === stepIdx) el.style.color = 'var(--accent-cyan)';
    }
  }, 22000);

  // 분석 대상이 'all'이면 status 필터 없이 최근 알람 사용
  let alert_ids = [];
  if (target === 'all') {
    // 최근 days일 알람 ID 조회
    const params = new URLSearchParams({ days, limit: 30 });
    const data = await api(`/api/alerts?${params}`);
    alert_ids = (data.alerts || []).map(a => a.id);
  }

  const body = alert_ids.length ? { alert_ids, days } : { days };
  const result = await api('/api/alerts/correlate', 'POST', body);

  // 폴링 타이머 정리 및 진행바 100%
  if (_corrPollingTimer) { clearInterval(_corrPollingTimer); _corrPollingTimer = null; }
  const bar = document.getElementById('corr-progress-bar');
  if (bar) bar.style.width = '100%';

  // 전역 상태 초기화 (완료)
  _corrStatus.running = false;

  if (!result.success) {
    _corrStatus.lastResult = null;
    _updateCorrStatusBar();
    resultDiv.innerHTML = `<div style="color:var(--critical);padding:12px;background:rgba(239,35,60,0.1);border-radius:8px;">⚠️ ${result.message || '분석 실패'}</div>`;
    return;
  }

  const raw = result.correlation || {};
  // LLM 응답이 다양한 형식으로 올 수 있으므로 방어적으로 추출
  const analysis = raw.analysis || {};
  const recs = raw.recommendations || {};
  const c = {
    overall_risk: (raw.overall_risk || raw.overall_risk_level || 'medium').toLowerCase(),
    lateral_movement_detected: raw.lateral_movement_detected ?? false,
    lateral_movement_evidence: raw.lateral_movement_evidence || '',
    attack_campaign: raw.attack_campaign ?? false,
    campaign_description: raw.campaign_description || '',
    apt_indicators: raw.apt_indicators ?? false,
    apt_description: raw.apt_description || '',
    insider_threat_risk: raw.insider_threat_risk ?? false,
    insider_description: raw.insider_description || '',
    attack_timeline: raw.attack_timeline || '',
    correlated_ips: raw.correlated_ips || raw.top_threat_ips || [],
    // LLM이 nested analysis로 반환한 경우도 처리
    key_findings: raw.key_findings || raw.attack_patterns ||
      (analysis.threat_indicators || []).map(t => t.details || t.indicator || String(t)) ||
      (analysis.potential_attack_scenarios || []),
    priority_actions: raw.priority_actions || raw.recommendations ||
      (recs.immediate_actions || []).concat(recs.long_term_hardening || []) || [],
    risk_summary: raw.risk_summary || raw.threat_summary || analysis.summary || '',
  };
  const stats = result.statistics || {};

  // 전역 상태: 결과 저장 → 알람 목록 상태바에 요약 표시
  _corrStatus.lastResult = {
    overall_risk: c.overall_risk,
    lateral_movement_detected: c.lateral_movement_detected,
    apt_indicators: c.apt_indicators,
    attack_campaign: c.attack_campaign,
    insider_threat_risk: c.insider_threat_risk,
    risk_summary: c.risk_summary,
    alert_count: result.alert_count,
    period_days: result.period_days,
  };
  _updateCorrStatusBar();

  // 위험도 색상
  const riskColor = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)' };
  const rc = riskColor[c.overall_risk] || 'var(--text-muted)';

  const boolBadge = (val, trueLabel, falseLabel) =>
    val ? `<span class="badge badge-critical">${trueLabel}</span>` : `<span class="badge badge-info">${falseLabel}</span>`;

  const listHtml = (arr) => arr?.length
    ? `<ul style="margin:6px 0 0 16px;font-size:13px;color:var(--text-secondary);">${arr.map(x => `<li>${escHtml(typeof x === 'object' ? JSON.stringify(x) : String(x))}</li>`).join('')}</ul>`
    : '<span style="color:var(--text-muted);font-size:13px;">없음</span>';

  resultDiv.innerHTML = `
    <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:10px;padding:16px;">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap;">
        <div style="font-size:22px;font-weight:700;color:${rc};">${(c.overall_risk || '?').toUpperCase()}</div>
        <div style="font-size:13px;color:var(--text-muted);">분석 알람 ${result.alert_count}개 | 기간 ${result.period_days}일</div>
        <div style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap;">
          ${boolBadge(c.lateral_movement_detected, '⚠️ 횡전개 감지', '✅ 횡전개 미감지')}
          ${boolBadge(c.apt_indicators, '🚨 APT 징후', '✅ APT 미감지')}
          ${boolBadge(c.attack_campaign, '🎯 캠페인 감지', '✅ 단발성')}
          ${boolBadge(c.insider_threat_risk, '👤 내부자 위협', '✅ 내부자 정상')}
        </div>
      </div>

      ${c.risk_summary ? `
      <div style="padding:10px 14px;background:rgba(255,200,0,0.07);border-left:3px solid ${rc};border-radius:4px;margin-bottom:12px;font-size:13px;color:var(--text-primary);">
        📋 ${escHtml(c.risk_summary)}
      </div>` : ''}

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
        <div style="background:var(--bg-secondary);border-radius:8px;padding:12px;">
          <div style="font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:6px;">📊 심각도 분포</div>
          ${Object.entries(stats.severity_distribution || {}).map(([s,n]) =>
            `<div style="display:flex;justify-content:space-between;font-size:12px;margin:2px 0;">
              <span>${severityBadge(s)}</span><span style="color:var(--text-secondary);">${n}건</span>
            </div>`).join('') || '<span style="color:var(--text-muted);font-size:12px;">없음</span>'}
          <div style="margin-top:6px;font-size:12px;color:#ffa500;">🌙 야간 알람: ${stats.after_hours_alerts || 0}건</div>
        </div>
        <div style="background:var(--bg-secondary);border-radius:8px;padding:12px;">
          <div style="font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:6px;">🌐 공통 IP</div>
          ${(stats.shared_ips || []).length
            ? (stats.shared_ips || []).map(ip => `<span class="ip-chip" onclick="lookupIP('${ip}')">${ip}</span>`).join(' ')
            : '<span style="color:var(--text-muted);font-size:12px;">공통 IP 없음</span>'}
          <div style="margin-top:6px;font-size:12px;color:var(--text-muted);">총 고유 IP: ${stats.total_unique_ips || 0}개</div>
        </div>
      </div>

      ${c.lateral_movement_evidence ? `
      <div style="margin-bottom:10px;">
        <div style="font-size:13px;font-weight:600;color:var(--high);margin-bottom:4px;">⚠️ 횡전개 근거</div>
        <div style="font-size:13px;color:var(--text-secondary);">${escHtml(c.lateral_movement_evidence)}</div>
      </div>` : ''}

      ${c.attack_timeline ? `
      <div style="margin-bottom:10px;">
        <div style="font-size:13px;font-weight:600;color:var(--accent-cyan);margin-bottom:4px;">🕒 공격 시나리오</div>
        <div style="font-size:13px;color:var(--text-secondary);">${escHtml(c.attack_timeline)}</div>
      </div>` : ''}

      ${c.key_findings?.length ? `
      <div style="margin-bottom:10px;">
        <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:4px;">🔍 핵심 발견사항</div>
        ${listHtml(c.key_findings)}
      </div>` : ''}

      ${c.priority_actions?.length ? `
      <div>
        <div style="font-size:13px;font-weight:600;color:var(--accent-green);margin-bottom:4px;">💡 즉각 조치사항</div>
        ${listHtml(c.priority_actions)}
      </div>` : ''}
    </div>`;
}

// ============================================================
async function fetchEmails() {
  // IMAP 모드: text input / OAuth 모드: select (multiple)
  const mailboxInput = document.getElementById('fetch-mailbox');
  const labelSelect = document.getElementById('fetch-label');

  let labelIds = [];
  let mailbox = 'INBOX';

  if (mailboxInput) {
    mailbox = mailboxInput.value.trim() || 'INBOX';
  } else if (labelSelect) {
    labelIds = Array.from(labelSelect.selectedOptions).map(o => o.value);
  }

  const query = document.getElementById('fetch-query')?.value || '';
  const maxResults = parseInt(document.getElementById('fetch-max')?.value || 50);
  const afterDate = document.getElementById('fetch-after')?.value || '';

  showToast('📥 메일 수집 중...', 'info');

  const result = await api('/api/gmail/fetch', 'POST', {
    label_ids: labelIds,
    mailbox,
    query,
    max_results: maxResults,
    after_date: afterDate,
    auto_analyze: true,
  });

  if (result.success) {
    showToast(`✅ ${result.saved}개 새 알람 수집 완료 (분석 중...)`, 'success');
    if (currentPage === 'dashboard') renderDashboard();
    else if (currentPage === 'alerts') renderAlerts(1);
  } else {
    showToast('❌ 수집 실패: ' + (result.detail || result.message || ''), 'error');
  }
}

// ============================================================
// 알람 액션
// ============================================================
async function reanalyzeAlert(alertId) {
  showToast('🔄 재분석 중...', 'info');
  const result = await api(`/api/alerts/${alertId}/reanalyze`, 'POST');
  if (result.success) {
    showToast('✅ 재분석 시작됨', 'success');
  }
}

async function deleteAlert(alertId) {
  const result = await api(`/api/alerts/${alertId}`, 'DELETE');
  if (result.success) {
    showToast('✅ 삭제 완료', 'success');
    if (currentPage === 'alerts') renderAlerts(currentAlertPage);
  }
}

// ============================================================
// 상관분석 전역 상태 업데이트
// ============================================================
function _updateCorrStatusBar() {
  const bar = document.getElementById('corr-status-bar');
  const btn = document.getElementById('corr-btn');
  if (!bar) return;
  if (_corrStatus.running) {
    bar.style.display = 'block';
    bar.innerHTML = `<span style="display:inline-flex;align-items:center;gap:8px;">
      <span class="spinner" style="width:14px;height:14px;border-width:2px;"></span>
      <span style="color:var(--accent-cyan);font-weight:600;">🕸 상관분석 진행 중...</span>
      <span style="color:var(--text-muted);">완료되면 결과가 여기에 표시됩니다</span>
    </span>`;
    if (btn) btn.disabled = true;
  } else if (_corrStatus.lastResult) {
    const r = _corrStatus.lastResult;
    const riskColor = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)' };
    const rc = riskColor[(r.overall_risk || '').toLowerCase()] || 'var(--text-muted)';
    const flags = [
      r.lateral_movement_detected ? '<span style="color:var(--high);">⚠️횡전개</span>' : null,
      r.apt_indicators ? '<span style="color:var(--critical);">🚨APT</span>' : null,
      r.attack_campaign ? '<span style="color:var(--high);">🎯캠페인</span>' : null,
      r.insider_threat_risk ? '<span style="color:var(--medium);">👤내부자</span>' : null,
    ].filter(Boolean).join(' ');
    bar.style.display = 'block';
    bar.innerHTML = `<span style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
      <span style="font-weight:700;color:${rc};">📊 상관분석 완료: ${(r.overall_risk || '?').toUpperCase()} 위험</span>
      <span style="color:var(--text-muted);">알람 ${r.alert_count || '?'}개 · ${r.period_days || '?'}일</span>
      ${flags}
      ${r.risk_summary ? `<span style="color:var(--text-secondary);font-size:11px;">${escHtml(String(r.risk_summary).slice(0,100))}${r.risk_summary.length > 100 ? '…' : ''}</span>` : ''}
      <button class="btn btn-secondary btn-sm" style="margin-left:auto;" onclick="showCorrelationModal()">🔍 상세보기</button>
    </span>`;
    if (btn) btn.disabled = false;
  } else {
    bar.style.display = 'none';
    if (btn) btn.disabled = false;
  }
}

// ============================================================
// 유틸리티
// ============================================================
function severityBadge(severity) {
  const classes = {
    critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium',
    low: 'badge-low', info: 'badge-info',
  };
  const cls = classes[severity] || 'badge-info';
  return `<span class="badge ${cls}">${(severity || 'info').toUpperCase()}</span>`;
}

function statusBadge(status) {
  const classes = {
    new: 'badge-new', analyzing: 'badge-info', analyzed: 'badge-analyzed',
    closed: 'badge-closed', reported: 'badge-analyzed',
  };
  const labels = {
    new: '신규', analyzing: '분석중', analyzed: '완료', closed: '종료', reported: '보고됨'
  };
  const cls = classes[status] || 'badge-new';
  return `<span class="badge ${cls}">${labels[status] || status || '신규'}</span>`;
}

async function loadAppTimezone() {
  try {
    const env = await api('/api/settings/env');
    if (env.app_timezone) _appTimezone = env.app_timezone;
    if (env.business_start_hour !== undefined) _businessStartHour = env.business_start_hour;
    if (env.business_end_hour !== undefined) _businessEndHour = env.business_end_hour;
  } catch(e) {}
}

function formatDate(dateStr) {
  if (!dateStr) return '-';
  try {
    // DB 저장값은 UTC naive (PostgreSQL timestamp without timezone)
    // 'Z' suffix가 없으면 UTC로 명시적 처리
    let isoStr = dateStr;
    if (!isoStr.endsWith('Z') && !isoStr.includes('+') && !isoStr.includes('-', 11)) {
      isoStr = isoStr + 'Z';  // UTC로 인식
    }
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return dateStr;

    const now = new Date();
    const diff = now - d;
    
    if (diff < 60000) return '방금 전';
    if (diff < 3600000) return Math.floor(diff / 60000) + '분 전';
    if (diff < 86400000) return Math.floor(diff / 3600000) + '시간 전';
    
    // 설정된 시간대로 변환하여 표시
    return d.toLocaleString('ko-KR', {
      timeZone: _appTimezone,
      month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
      hour12: false,
    });
  } catch { return dateStr; }
}

function formatDateFull(dateStr) {
  if (!dateStr) return '-';
  try {
    let isoStr = dateStr;
    if (!isoStr.endsWith('Z') && !isoStr.includes('+') && !isoStr.includes('-', 11)) {
      isoStr = isoStr + 'Z';
    }
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleString('ko-KR', {
      timeZone: _appTimezone,
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    }) + ` (${_appTimezone})`;
  } catch { return dateStr; }
}

function escHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function generatePagination(current, total, callback) {
  if (total <= 1) return '';
  
  let html = '<div class="pagination">';
  html += `<button class="page-btn" onclick="${callback}(${current-1})" ${current === 1 ? 'disabled' : ''}>◀</button>`;
  
  for (let i = Math.max(1, current - 2); i <= Math.min(total, current + 2); i++) {
    html += `<button class="page-btn ${i === current ? 'active' : ''}" onclick="${callback}(${i})">${i}</button>`;
  }
  
  html += `<button class="page-btn" onclick="${callback}(${current+1})" ${current === total ? 'disabled' : ''}>▶</button>`;
  html += '</div>';
  return html;
}

function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  const item = document.createElement('div');
  item.className = `toast-item toast-${type}`;
  item.textContent = message;
  toast.appendChild(item);
  
  setTimeout(() => {
    item.style.opacity = '0';
    item.style.transition = 'opacity 0.3s';
    setTimeout(() => item.remove(), 300);
  }, 4000);
}

function openModal(content) {
  const overlay = document.getElementById('modal-overlay');
  const modal = document.getElementById('modal-content');
  overlay.classList.remove('hidden');
  modal.innerHTML = content;
}

function closeModal(event) {
  if (!event || event.target === document.getElementById('modal-overlay')) {
    document.getElementById('modal-overlay').classList.add('hidden');
  }
}

// ============================================================
// 초기화
// ============================================================
async function checkLLMStatus() {
  const status = await api('/api/llm/status');
  const dot = document.getElementById('llm-status-dot');
  const text = document.getElementById('llm-status-text');
  
  if (dot && text) {
    if (status.connected) {
      dot.className = 'status-dot';
      dot.style.display = 'inline-block';
      const modelName = (status.models || [])[0] || 'Gemma4';
      text.textContent = `${modelName.split(':')[0]}`;
    } else {
      dot.className = 'status-dot warning';
      dot.style.display = 'inline-block';
      text.textContent = 'Gemma4: 연결 안됨';
    }
  }
}

async function checkDBStatus() {
  const dot = document.getElementById('db-status-dot');
  const text = document.getElementById('db-status-text');
  const sysInfo = await api('/api/settings/system-info');
  
  if (dot && text) {
    // health check로 DB 동작 간접 확인
    const health = await api('/health');
    if (health.status === 'healthy') {
      dot.className = 'status-dot';
      dot.style.display = 'inline-block';
      text.textContent = `DB: ${sysInfo.db_type || 'SQLite'}`;
    } else {
      dot.className = 'status-dot error';
      dot.style.display = 'inline-block';
      text.textContent = 'DB: 오류';
    }
    // 시스템 정보 표시
    const sysEl = document.getElementById('sys-info-text');
    if (sysEl) {
      sysEl.textContent = `UI:${sysInfo.frontend_port||61001} API:${sysInfo.api_port||8000}`;
    }
  }
}

// 초기 렌더링
window.addEventListener('DOMContentLoaded', async () => {
  // 시간대 설정 먼저 로드 (formatDate에서 사용)
  await loadAppTimezone();

  navigate('dashboard');
  checkLLMStatus();
  checkDBStatus();
  
  // 5분마다 상태 체크
  setInterval(checkLLMStatus, 300000);
  setInterval(checkDBStatus, 300000);
});
