/**
 * Security Mail Analyzer - Frontend Application
 * NVIDIA GB10 최적화 보안 알람 분석 대시보드
 */

const API_BASE = '';
let currentPage = 'dashboard';
let currentAlertPage = 1;
let chatSessionId = null;
let dashboardCharts = {};

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
async function renderAlerts(page = 1) {
  currentAlertPage = page;
  
  const severity = document.getElementById('filter-severity')?.value || '';
  const status = document.getElementById('filter-status')?.value || '';
  const fp = document.getElementById('filter-fp')?.value || '';
  const search = document.getElementById('filter-search')?.value || '';
  const days = document.getElementById('filter-days')?.value || '30';
  
  const params = new URLSearchParams({
    page,
    limit: 25,
    days,
    ...(severity && { severity }),
    ...(status && { status }),
    ...(fp && { is_false_positive: fp }),
    ...(search && { search }),
  });
  
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
  
  // 페이지네이션
  const totalPages = data.pages || 1;
  const paginationHtml = generatePagination(page, totalPages, 'renderAlerts');
  
  document.getElementById('page-content').innerHTML = `
    <div class="card" style="margin-bottom:16px;">
      <div class="filter-bar">
        <input class="form-input" id="filter-search" placeholder="🔍 검색..." value="" style="width:200px;" onkeydown="if(event.key==='Enter')renderAlerts(1)">
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
          <option value="30" selected>30일</option>
          <option value="90">90일</option>
          <option value="365">365일</option>
        </select>
        <button class="btn btn-primary btn-sm" onclick="renderAlerts(1)">적용</button>
        <span style="margin-left:auto;color:var(--text-muted);font-size:12px;">
          총 ${data.total || 0}건
        </span>
      </div>
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
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${paginationHtml}
    </div>
  `;
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
          ${statusBadge(alert.status)}
        </div>
      </div>
      <button class="modal-close" onclick="closeModal()">×</button>
    </div>
    
    <div class="detail-section">
      <div class="detail-title">📧 메일 정보</div>
      <div class="detail-content" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
        <div><span style="color:var(--text-muted);">발신자:</span> ${escHtml(alert.sender || '-')}</div>
        <div><span style="color:var(--text-muted);">수신시간:</span> ${formatDate(alert.received_at)}</div>
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
function renderChat() {
  if (!chatSessionId) {
    chatSessionId = 'session_' + Date.now();
  }
  
  document.getElementById('page-content').innerHTML = `
    <div class="grid-2" style="height:calc(100vh - 140px);">
      <!-- 채팅 -->
      <div class="card" style="display:flex;flex-direction:column;height:100%;">
        <div class="card-title">
          🤖 AI 보안 분석 채팅
          <button class="btn btn-secondary btn-sm" style="margin-left:auto;" onclick="newChatSession()">새 세션</button>
        </div>
        
        <div id="chat-messages" style="flex:1;overflow-y:auto;">
          <div class="chat-message assistant">
            <div class="chat-avatar">🤖</div>
            <div class="chat-bubble">
              안녕하세요! 보안 AI 어시스턴트입니다.<br><br>
              보안 알람 분석, 위협 평가, 대응 방안 등 무엇이든 질문해 주세요.<br><br>
              <strong>예시 질문:</strong><br>
              • 최근 가장 위협적인 공격 패턴이 무엇인가요?<br>
              • 특정 IP가 악성인지 판단해 주세요<br>
              • 오탐을 줄이는 방법은?<br>
              • 알람 대응 우선순위를 알려주세요
            </div>
          </div>
        </div>
        
        <div style="display:flex;gap:8px;margin-top:12px;">
          <select class="form-select" id="chat-model" style="width:160px;">
            <option value="">기본 모델</option>
          </select>
          <input class="form-input" id="chat-input" placeholder="질문을 입력하세요..." 
                 style="flex:1;" onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendChat();}">
          <button class="btn btn-primary" onclick="sendChat()">전송</button>
        </div>
      </div>
      
      <!-- 세션 목록 & 컨텍스트 -->
      <div style="display:flex;flex-direction:column;gap:16px;height:100%;overflow:hidden;">
        <div class="card" style="flex:1;overflow-y:auto;">
          <div class="card-title">📋 빠른 분석 질문</div>
          <div style="display:flex;flex-direction:column;gap:6px;">
            ${[
              '최근 7일 가장 위험한 알람은?',
              'Critical 알람들의 공통 패턴 분석',
              '오탐으로 분류된 알람 패턴은?',
              '반복 알람의 원인 분석',
              '보안 권고사항 top 5',
              'IP 위협 트렌드 분석',
            ].map(q => `
              <button class="btn btn-secondary btn-sm" style="text-align:left;justify-content:flex-start;" 
                      onclick="setQuickChat('${q}')">
                💬 ${q}
              </button>`).join('')}
          </div>
        </div>
        
        <div class="card" style="flex:1;overflow-y:auto;">
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

async function sendChat() {
  const input = document.getElementById('chat-input');
  const text = input?.value?.trim();
  if (!text) return;
  
  input.value = '';
  
  appendChatMessage('user', text);
  
  const model = document.getElementById('chat-model')?.value || null;
  
  // 타이핑 표시
  const typingId = 'typing_' + Date.now();
  appendChatMessage('assistant', '...', typingId);
  
  const result = await api('/api/llm/chat', 'POST', {
    messages: [{ role: 'user', content: text }],
    session_id: chatSessionId,
    model: model || undefined,
  });
  
  // 타이핑 제거 후 실제 응답 표시
  const typingEl = document.getElementById(typingId);
  if (typingEl) typingEl.closest('.chat-message').remove();
  
  appendChatMessage('assistant', result.response || '응답을 받지 못했습니다.');
}

function appendChatMessage(role, content, id = null) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  
  const div = document.createElement('div');
  div.className = `chat-message ${role}`;
  if (id) div.id = id;
  
  div.innerHTML = `
    <div class="chat-avatar">${role === 'user' ? '👤' : '🤖'}</div>
    <div class="chat-bubble">${content === '...' ? '<div class="spinner" style="width:16px;height:16px;"></div>' : escHtml(content)}</div>
  `;
  
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function newChatSession() {
  chatSessionId = 'session_' + Date.now();
  const container = document.getElementById('chat-messages');
  if (container) {
    container.innerHTML = `
      <div class="chat-message assistant">
        <div class="chat-avatar">🤖</div>
        <div class="chat-bubble">새 채팅 세션이 시작되었습니다.</div>
      </div>
    `;
  }
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

function openChatWithContext(alertId) {
  navigate('chat');
  setTimeout(() => {
    const input = document.getElementById('chat-input');
    if (input) {
      input.value = `알람 ID ${alertId}에 대해 분석해줘`;
      input.focus();
    }
  }, 500);
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
  const labels = await api('/api/gmail/labels');
  const envData = await api('/api/settings/env');
  
  const labelOptions = (labels.labels || []).map(l => 
    `<option value="${l.id}">${l.name}</option>`
  ).join('');
  
  const connectedHtml = status.connected 
    ? `<div style="color:var(--accent-green);font-size:14px;font-weight:bold;">✅ 연결됨 ${status.user ? `(${status.user})` : ''}</div>`
    : `<div style="color:var(--critical);font-size:14px;font-weight:bold;">❌ 연결 안됨 - 아래에서 인증하세요</div>`;
  
  document.getElementById('page-content').innerHTML = `
    <div class="card" style="margin-bottom:16px;">
      <div class="card-title">📧 Gmail 연결 상태</div>
      ${connectedHtml}
      <div style="margin-top:12px;font-size:13px;color:var(--text-muted);">${status.message || ''}</div>
    </div>
    
    <div class="tabs">
      <div class="tab active" onclick="switchTab('gmail-oauth', this)">OAuth 인증</div>
      <div class="tab" onclick="switchTab('gmail-apppass', this)">App Password</div>
      <div class="tab" onclick="switchTab('gmail-fetch', this)">수집 설정</div>
    </div>
    
    <div id="gmail-oauth" class="tab-content">
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
    
    <div id="gmail-apppass" class="tab-content hidden">
      <div class="card">
        <div class="card-title">🔑 App Password 설정 (SMTP/IMAP)</div>
        <div style="font-size:13px;color:var(--text-muted);margin-bottom:16px;line-height:1.8;">
          Gmail 계정에서 2단계 인증 활성화 후 앱 비밀번호를 생성하세요.
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Gmail 계정</label>
            <input class="form-input" id="ap-email" type="email" placeholder="your@gmail.com" value="${envData.gmail_user || ''}">
          </div>
          <div class="form-group">
            <label class="form-label">앱 비밀번호</label>
            <input class="form-input" id="ap-password" type="password" placeholder="16자리 앱 비밀번호">
          </div>
        </div>
        <button class="btn btn-primary" onclick="saveAppPassword()">💾 저장</button>
      </div>
    </div>
    
    <div id="gmail-fetch" class="tab-content hidden">
      <div class="card">
        <div class="card-title">⚙️ 메일 수집 설정</div>
        <div class="form-group">
          <label class="form-label">수집할 메일함 (레이블)</label>
          <select class="form-select" id="fetch-label" multiple style="height:120px;">
            ${labelOptions}
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Gmail 검색 쿼리 (예: subject:alert OR subject:security)</label>
          <input class="form-input" id="fetch-query" placeholder="subject:security OR subject:alert" value="${envData.gmail_query || ''}">
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">최대 수집 건수</label>
            <input class="form-input" id="fetch-max" type="number" value="50" min="1" max="200">
          </div>
          <div class="form-group">
            <label class="form-label">수집 기간 (YYYY/MM/DD)</label>
            <input class="form-input" id="fetch-after" placeholder="2024/01/01">
          </div>
        </div>
        <button class="btn btn-primary" onclick="fetchEmails()">📥 지금 수집</button>
        <button class="btn btn-secondary" style="margin-left:8px;" onclick="saveFetchSettings()">💾 설정 저장</button>
      </div>
    </div>
  `;
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
  const password = document.getElementById('ap-password')?.value;
  
  const result = await api('/api/settings/env', 'POST', {
    gmail_user: email,
    gmail_app_password: password,
    smtp_user: email,
    smtp_password: password,
    smtp_host: 'smtp.gmail.com',
    smtp_port: 587,
  });
  
  if (result.success) {
    showToast('✅ App Password 저장 완료', 'success');
  }
}

async function saveFetchSettings() {
  const query = document.getElementById('fetch-query')?.value?.trim();
  const result = await api('/api/settings/env', 'POST', { gmail_query: query });
  if (result.success) showToast('✅ 수집 설정 저장 완료', 'success');
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
  
  const modelOptions = (llmModels.models || []).map(m => `<option value="${m}">${m}</option>`).join('');
  
  document.getElementById('page-content').innerHTML = `
    <div class="grid-2">
      <!-- LLM 설정 -->
      <div class="card">
        <div class="card-title">🤖 로컬 LLM (Ollama) 설정</div>
        <div style="margin-bottom:12px;padding:10px;border-radius:6px;background:${llmStatus.connected ? 'rgba(6,214,160,0.1)' : 'rgba(239,35,60,0.1)'};border:1px solid ${llmStatus.connected ? 'rgba(6,214,160,0.3)' : 'rgba(239,35,60,0.3)'};">
          <div style="color:${llmStatus.connected ? 'var(--accent-green)' : 'var(--critical)'};">
            ${llmStatus.connected ? '✅ 연결됨' : '❌ 연결 안됨'}
          </div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">${llmStatus.message || llmStatus.error || ''}</div>
        </div>
        <div class="form-group">
          <label class="form-label">Ollama URL</label>
          <input class="form-input" id="llm-url" value="${envData.ollama_url || 'http://localhost:11434'}">
        </div>
        <div class="form-group">
          <label class="form-label">기본 모델</label>
          <select class="form-select" id="llm-model">
            <option value="llama3.2:3b">llama3.2:3b (추천 - 소형)</option>
            <option value="llama3.1:8b">llama3.1:8b</option>
            <option value="mistral:7b">mistral:7b</option>
            <option value="qwen2.5:7b">qwen2.5:7b (한국어 우수)</option>
            <option value="gemma3:9b">gemma3:9b</option>
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
        NVIDIA GB10 GPU로 가속됩니다. 권장 모델: llama3.2:3b (소형), qwen2.5:7b (한국어)
      </div>
      <div style="display:flex;gap:8px;margin-bottom:12px;">
        <input class="form-input" id="pull-model-name" placeholder="모델명 (예: llama3.2:3b)" value="llama3.2:3b">
        <button class="btn btn-primary" onclick="pullModel()">📥 다운로드</button>
      </div>
      <div id="pull-progress" style="display:none;">
        <div class="progress-bar" style="margin-bottom:8px;">
          <div class="progress-fill" id="pull-bar" style="width:0%"></div>
        </div>
        <div id="pull-status" style="font-size:12px;color:var(--text-muted);"></div>
      </div>
    </div>
  `;
}

async function saveLLMSettings() {
  const result = await api('/api/settings/env', 'POST', {
    ollama_url: document.getElementById('llm-url')?.value,
    ollama_model: document.getElementById('llm-model')?.value,
  });
  if (result.success) showToast('✅ LLM 설정 저장 완료', 'success');
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
async function fetchEmails() {
  const labelSelect = document.getElementById('fetch-label');
  const labelIds = labelSelect ? Array.from(labelSelect.selectedOptions).map(o => o.value) : [];
  const query = document.getElementById('fetch-query')?.value || '';
  const maxResults = parseInt(document.getElementById('fetch-max')?.value || 50);
  const afterDate = document.getElementById('fetch-after')?.value || '';
  
  showToast('📥 메일 수집 중...', 'info');
  
  const result = await api('/api/gmail/fetch', 'POST', {
    label_ids: labelIds,
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
    showToast('수집 실패: ' + result.detail, 'error');
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

function formatDate(dateStr) {
  if (!dateStr) return '-';
  try {
    const d = new Date(dateStr);
    const now = new Date();
    const diff = now - d;
    
    if (diff < 60000) return '방금 전';
    if (diff < 3600000) return Math.floor(diff / 60000) + '분 전';
    if (diff < 86400000) return Math.floor(diff / 3600000) + '시간 전';
    
    return d.toLocaleDateString('ko-KR', { 
      month: '2-digit', day: '2-digit', 
      hour: '2-digit', minute: '2-digit' 
    });
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
  
  if (status.connected) {
    dot.classList.remove('error', 'warning');
    text.textContent = `LLM: ${(status.models || []).length}개 모델`;
  } else {
    dot.classList.add('warning');
    text.textContent = 'LLM: 연결 안됨';
  }
}

// 초기 렌더링
window.addEventListener('DOMContentLoaded', async () => {
  navigate('dashboard');
  checkLLMStatus();
  
  // 5분마다 LLM 상태 체크
  setInterval(checkLLMStatus, 300000);
});
