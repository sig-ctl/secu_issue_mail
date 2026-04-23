#!/bin/bash
# ============================================================
# NVIDIA Container Runtime 설정 스크립트
# Ollama GPU 가속을 위해 필요
# 실행: sudo bash docker/setup-nvidia-runtime.sh
# ============================================================

set -e
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo "=== NVIDIA Container Runtime 설정 ==="
echo ""

# 1. NVIDIA Container Toolkit 설치 확인
if ! command -v nvidia-ctk > /dev/null 2>&1; then
    log_warn "NVIDIA Container Toolkit이 설치되지 않았습니다."
    log_info "설치 중..."
    
    # Ubuntu/Debian
    if command -v apt-get > /dev/null 2>&1; then
        curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
        curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
            sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
            tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
        apt-get update
        apt-get install -y nvidia-container-toolkit
        log_info "✅ NVIDIA Container Toolkit 설치 완료"
    else
        log_error "apt-get을 찾을 수 없습니다. 수동 설치가 필요합니다:"
        log_error "https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/"
        exit 1
    fi
else
    log_info "✅ NVIDIA Container Toolkit 이미 설치됨: $(nvidia-ctk --version 2>/dev/null)"
fi

echo ""
# 2. Docker Runtime 설정
log_info "Docker NVIDIA Runtime 설정 중..."
nvidia-ctk runtime configure --runtime=docker

# 3. daemon.json 확인
log_info "현재 /etc/docker/daemon.json:"
cat /etc/docker/daemon.json 2>/dev/null || echo "(파일 없음)"
echo ""

# 4. Docker 재시작
log_info "Docker 데몬 재시작 중..."
systemctl restart docker
sleep 3

# 5. 확인
log_info "NVIDIA Runtime 확인:"
docker info 2>/dev/null | grep -i "nvidia\|runtime" | head -5

echo ""
log_info "✅ 설정 완료!"
log_info "이제 'sudo ./start.sh gpu' 로 GPU 모드 실행 가능"
