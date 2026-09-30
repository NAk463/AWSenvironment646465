#!/usr/bin/env bash
# =============================================================================
# AWS ローカル再現環境 セットアップスクリプト
#
# 対応 OS : Ubuntu / Debian (WSL2 含む), macOS (Homebrew)
# 使い方  : ./install.sh [--only c1,c2] [--skip c1,c2] [--upgrade] [--dry-run] [-y]
#
# コンポーネント (実行順):
#   base       jq / git / unzip / python3 / pipx などの基本ツール
#   docker     Docker Engine + Compose (macOS は Colima + docker CLI)
#   awscli     AWS CLI v2
#   pytools    pipx 経由: localstack CLI, awslocal, samlocal/SAM CLI, tflocal
#   terraform  Terraform (公式バイナリ, SHA256 検証付き)
#   cdk        Node.js + AWS CDK + cdklocal
#   profile    ~/.aws に "localstack" プロファイルを作成
#   env        docker compose 用の .env を作成
# =============================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_BIN="${HOME}/.local/bin"
LOCAL_REGION="${AWS_LOCAL_REGION:-ap-northeast-1}"
NODE_MAJOR="${NODE_MAJOR:-22}"

ALL_COMPONENTS=(base docker awscli pytools terraform cdk profile env)
PIPX_PACKAGES=(localstack awscli-local aws-sam-cli aws-sam-cli-local terraform-local)
NPM_PACKAGES=(aws-cdk aws-cdk-local)

DRY_RUN=0
UPGRADE=0
ASSUME_YES=0
ONLY=""
SKIP=""

# ----------------------------------------------------------------------------
# ログ / ユーティリティ
# ----------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_INFO=$'\e[36m'; C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_RST=$'\e[0m'
else
  C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_RST=""
fi
info() { printf '%s[INFO]%s %s\n' "$C_INFO" "$C_RST" "$*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_OK" "$C_RST" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_RST" "$*" >&2; }
err()  { printf '%s[ERR ]%s %s\n' "$C_ERR" "$C_RST" "$*" >&2; }

run() {
  if (( DRY_RUN )); then
    printf '  + %s\n' "$*"
  else
    "$@"
  fi
}

has() { command -v "$1" >/dev/null 2>&1; }

usage() {
  sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'
オプション:
  --only a,b    指定したコンポーネントのみ実行
  --skip a,b    指定したコンポーネントをスキップ
  --upgrade     インストール済みのツールも最新版に更新
  --dry-run     実行するコマンドを表示するだけ
  -y, --yes     確認プロンプトを省略
  -h, --help    このヘルプを表示

環境変数:
  AWS_LOCAL_REGION  localstack プロファイルのリージョン (既定: ap-northeast-1)
  NODE_MAJOR        Linux で導入する Node.js のメジャーバージョン (既定: 22)
EOF
}

parse_args() {
  while (($#)); do
    case "$1" in
      --only)    ONLY="${2:?--only には値が必要です}"; shift ;;
      --only=*)  ONLY="${1#*=}" ;;
      --skip)    SKIP="${2:?--skip には値が必要です}"; shift ;;
      --skip=*)  SKIP="${1#*=}" ;;
      --upgrade) UPGRADE=1 ;;
      --dry-run) DRY_RUN=1 ;;
      -y|--yes)  ASSUME_YES=1 ;;
      -h|--help) usage; exit 0 ;;
      *) err "不明なオプション: $1"; usage; exit 2 ;;
    esac
    shift
  done

  local c
  for c in ${ONLY//,/ } ${SKIP//,/ }; do
    [[ " ${ALL_COMPONENTS[*]} " == *" $c "* ]] || { err "不明なコンポーネント: $c"; exit 2; }
  done
}

selected() {
  local c="$1"
  if [[ -n "$ONLY" ]]; then
    [[ ",$ONLY," == *",$c,"* ]] || return 1
  fi
  [[ ",$SKIP," != *",$c,"* ]]
}

# ----------------------------------------------------------------------------
# 環境判定
# ----------------------------------------------------------------------------
OS=""       # debian | macos
ARCH=""     # amd64 | arm64
IS_WSL=0
SUDO=""

detect_platform() {
  case "$(uname -s)" in
    Darwin) OS=macos ;;
    Linux)
      # shellcheck disable=SC1091
      . /etc/os-release
      if [[ "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" || " ${ID_LIKE:-} " == *" debian "* ]]; then
        OS=debian
      else
        err "未対応のディストリビューションです: ${PRETTY_NAME:-unknown} (Ubuntu/Debian 系のみ対応)"
        exit 1
      fi
      grep -qi microsoft /proc/version 2>/dev/null && IS_WSL=1
      ;;
    *) err "未対応の OS です: $(uname -s)"; exit 1 ;;
  esac

  case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) err "未対応の CPU アーキテクチャです: $(uname -m)"; exit 1 ;;
  esac

  if [[ "$OS" == debian && "$(id -u)" -ne 0 ]]; then
    has sudo || { err "sudo が見つかりません。root で実行するか sudo を導入してください。"; exit 1; }
    SUDO="sudo"
  fi
}

apt_install() {
  run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

brew_install() {
  local pkg
  for pkg in "$@"; do
    if brew list "${pkg##*/}" >/dev/null 2>&1; then
      (( UPGRADE )) && run brew upgrade "$pkg" || true
    else
      run brew install "$pkg"
    fi
  done
}

ensure_path() {
  mkdir -p "$LOCAL_BIN"
  case ":$PATH:" in *":$LOCAL_BIN:"*) ;; *) export PATH="$LOCAL_BIN:$PATH" ;; esac

  local rc line='export PATH="$HOME/.local/bin:$PATH"  # added by aws-local install.sh'
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [[ -f "$rc" ]] || continue
    grep -qF 'added by aws-local install.sh' "$rc" && continue
    info "$rc に ~/.local/bin を PATH に追加します"
    (( DRY_RUN )) || printf '\n%s\n' "$line" >> "$rc"
  done
}

ensure_brew() {
  [[ "$OS" == macos ]] || return 0
  if ! has brew; then
    info "Homebrew をインストールします"
    run env NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  fi
  local b
  for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    [[ -x "$b" ]] && { eval "$("$b" shellenv)"; break; }
  done
}

# ----------------------------------------------------------------------------
# コンポーネント
# ----------------------------------------------------------------------------
install_base() {
  if [[ "$OS" == debian ]]; then
    run $SUDO apt-get update -y
    local pkgs=(ca-certificates curl gnupg unzip jq git python3 python3-venv)
    if apt-cache show pipx >/dev/null 2>&1; then
      pkgs+=(pipx)
    else
      pkgs+=(python3-pip)
    fi
    apt_install "${pkgs[@]}"
    if ! has pipx && (( ! DRY_RUN )); then
      python3 -m pip install --user pipx
    fi
  else
    brew_install jq git python pipx
  fi
  ok "base"
}

install_docker() {
  if [[ "$OS" == debian ]]; then
    if has docker && docker compose version >/dev/null 2>&1 && (( ! UPGRADE )); then
      ok "docker は導入済みです ($(docker --version))"
    else
      if (( IS_WSL )); then
        warn "WSL2 を検出しました。Docker Desktop の WSL Integration を使う場合は --skip docker を指定してください。"
      fi
      info "Docker Engine を公式スクリプト (get.docker.com) でインストールします"
      local tmp; tmp="$(mktemp)"
      run curl -fsSL https://get.docker.com -o "$tmp"
      run $SUDO sh "$tmp"
      rm -f "$tmp"
    fi

    if [[ "$(id -u)" -ne 0 ]] && ! id -nG | tr ' ' '\n' | grep -qx docker; then
      info "ユーザー $USER を docker グループに追加します (反映には再ログインが必要)"
      run $SUDO usermod -aG docker "$USER"
    fi

    if has systemctl && [[ -d /run/systemd/system ]]; then
      run $SUDO systemctl enable --now docker
    elif has service; then
      run $SUDO service docker start || warn "docker デーモンを起動できませんでした"
    fi
  else
    # macOS: GUI 不要でスクリプトから制御できる Colima を採用
    if has docker && docker info >/dev/null 2>&1 && (( ! UPGRADE )); then
      ok "docker は利用可能です (Docker Desktop などを検出)"
      return 0
    fi
    brew_install colima docker docker-compose

    # docker compose (プラグイン形式) を有効化
    local cfg="$HOME/.docker/config.json" plugdir
    plugdir="$(brew --prefix)/lib/docker/cli-plugins"
    if (( ! DRY_RUN )); then
      mkdir -p "$(dirname "$cfg")"
      [[ -s "$cfg" ]] || echo '{}' > "$cfg"
      local tmp; tmp="$(mktemp)"
      jq --arg d "$plugdir" '.cliPluginsExtraDirs = ((.cliPluginsExtraDirs // []) + [$d] | unique)' "$cfg" > "$tmp" && mv "$tmp" "$cfg"
    fi

    if ! colima status >/dev/null 2>&1; then
      info "Colima を起動します (CPU 2 / メモリ 4GB)"
      run colima start --cpu 2 --memory 4
    fi
  fi
  ok "docker"
}

install_awscli() {
  if has aws && aws --version 2>&1 | grep -q '^aws-cli/2' && (( ! UPGRADE )); then
    ok "AWS CLI v2 は導入済みです ($(aws --version 2>&1 | cut -d' ' -f1))"
    return 0
  fi

  if [[ "$OS" == macos ]]; then
    brew_install awscli
  else
    local arch tmp
    [[ "$ARCH" == amd64 ]] && arch=x86_64 || arch=aarch64
    tmp="$(mktemp -d)"
    info "AWS CLI v2 を ~/.local/aws-cli にインストールします (sudo 不要)"
    run curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${arch}.zip" -o "$tmp/awscliv2.zip"
    run unzip -q "$tmp/awscliv2.zip" -d "$tmp"
    run "$tmp/aws/install" --install-dir "$HOME/.local/aws-cli" --bin-dir "$LOCAL_BIN" --update
    rm -rf "$tmp"
  fi
  ok "awscli"
}

install_pytools() {
  if (( DRY_RUN )) && ! has pipx; then
    printf '  + pipx install %s\n' "${PIPX_PACKAGES[@]}"
    return 0
  fi
  has pipx || { err "pipx が見つかりません。先に base を実行してください。"; return 1; }
  run pipx ensurepath >/dev/null

  local pkg
  for pkg in "${PIPX_PACKAGES[@]}"; do
    if pipx list --short 2>/dev/null | awk '{print $1}' | grep -qx "$pkg"; then
      if (( UPGRADE )); then
        run pipx upgrade "$pkg"
      else
        ok "$pkg は導入済みです"
      fi
    else
      info "pipx install $pkg"
      run pipx install "$pkg"
    fi
  done
  ok "pytools (localstack, awslocal, sam, samlocal, tflocal)"
}

install_terraform() {
  if has terraform && (( ! UPGRADE )); then
    ok "terraform は導入済みです ($(terraform version | head -n1))"
    return 0
  fi

  if [[ "$OS" == macos ]]; then
    run brew tap hashicorp/tap
    brew_install hashicorp/tap/terraform
  else
    local ver base tmp zip
    if (( DRY_RUN )); then
      ver="<latest>"
    else
      ver="$(curl -fsSL https://checkpoint-api.hashicorp.com/v1/check/terraform | jq -r '.current_version')"
    fi
    [[ -n "$ver" && "$ver" != null ]] || { err "Terraform の最新バージョンを取得できませんでした"; return 1; }
    base="https://releases.hashicorp.com/terraform/${ver}"
    zip="terraform_${ver}_linux_${ARCH}.zip"
    tmp="$(mktemp -d)"
    info "Terraform ${ver} を ~/.local/bin にインストールします"
    run curl -fsSL "${base}/${zip}" -o "$tmp/$zip"
    run curl -fsSL "${base}/terraform_${ver}_SHA256SUMS" -o "$tmp/SHA256SUMS"
    if (( ! DRY_RUN )); then
      (cd "$tmp" && grep " ${zip}\$" SHA256SUMS | sha256sum -c --status) \
        || { err "Terraform の SHA256 検証に失敗しました"; rm -rf "$tmp"; return 1; }
    fi
    run unzip -oq "$tmp/$zip" terraform -d "$LOCAL_BIN"
    rm -rf "$tmp"
  fi
  ok "terraform"
}

node_major() {
  has node || { echo 0; return; }
  node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0
}

install_cdk() {
  if (( $(node_major) < 20 )); then
    info "Node.js ${NODE_MAJOR}.x をインストールします"
    if [[ "$OS" == macos ]]; then
      brew_install node
    else
      local tmp; tmp="$(mktemp)"
      run curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" -o "$tmp"
      run $SUDO -E bash "$tmp"
      rm -f "$tmp"
      apt_install nodejs
    fi
  else
    ok "Node.js は導入済みです ($(node --version))"
  fi

  # グローバル npm を ~/.local に入れて sudo を不要にする
  local pkg missing=()
  for pkg in "${NPM_PACKAGES[@]}"; do
    if (( UPGRADE )) || ! npm ls -g --prefix "$HOME/.local" "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if ((${#missing[@]})); then
    run npm install -g --prefix "$HOME/.local" "${missing[@]}"
  fi
  ok "cdk (cdk, cdklocal)"
}

configure_profile() {
  has aws || { warn "aws コマンドが無いため localstack プロファイルの作成をスキップします"; return 0; }
  info "AWS プロファイル 'localstack' を設定します (region=${LOCAL_REGION}, endpoint=http://localhost:4566)"
  run aws configure set aws_access_key_id test --profile localstack
  run aws configure set aws_secret_access_key test --profile localstack
  run aws configure set region "$LOCAL_REGION" --profile localstack
  run aws configure set output json --profile localstack
  run aws configure set endpoint_url http://localhost:4566 --profile localstack
  ok "profile (aws --profile localstack ... で LocalStack に接続できます)"
}

create_env_file() {
  local env="$SCRIPT_DIR/.env"
  if [[ -f "$env" ]]; then
    ok ".env は既に存在します ($env)"
    return 0
  fi
  run cp "$SCRIPT_DIR/.env.example" "$env"
  ok ".env を作成しました。LocalStack を使う場合は LOCALSTACK_AUTH_TOKEN を設定してください"
}

# ----------------------------------------------------------------------------
# メイン
# ----------------------------------------------------------------------------
main() {
  parse_args "$@"
  detect_platform

  info "OS=${OS} ARCH=${ARCH} WSL=${IS_WSL} DRY_RUN=${DRY_RUN} UPGRADE=${UPGRADE}"
  local plan=() c
  for c in "${ALL_COMPONENTS[@]}"; do selected "$c" && plan+=("$c"); done
  info "実行するコンポーネント: ${plan[*]:-(なし)}"

  if (( ! ASSUME_YES && ! DRY_RUN )) && [[ -t 0 ]]; then
    read -r -p "続行しますか? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { info "中止しました"; exit 0; }
  fi

  ensure_brew
  ensure_path

  local failed=() rc
  for c in "${plan[@]}"; do
    printf '\n'; info "===== ${c} ====="
    # サブシェル + set -e で各コンポーネントを独立実行し、失敗しても次へ進む
    set +e
    (
      set -e
      case "$c" in
        base)      install_base ;;
        docker)    install_docker ;;
        awscli)    install_awscli ;;
        pytools)   install_pytools ;;
        terraform) install_terraform ;;
        cdk)       install_cdk ;;
        profile)   configure_profile ;;
        env)       create_env_file ;;
      esac
    )
    rc=$?
    set -e
    (( rc == 0 )) || { err "${c} が失敗しました (exit ${rc})"; failed+=("$c"); }
  done

  printf '\n'
  if (( ! DRY_RUN )) && [[ -x "$SCRIPT_DIR/scripts/verify.sh" ]]; then
    "$SCRIPT_DIR/scripts/verify.sh" || true
  fi

  if ((${#failed[@]})); then
    local retry; retry="$(IFS=,; echo "${failed[*]}")"
    err "失敗したコンポーネント: ${failed[*]}  (./install.sh --only ${retry} で再実行できます)"
    exit 1
  fi
  ok "セットアップが完了しました。新しいシェルを開くか 'source ~/.bashrc' で PATH を反映してください。"
}

main "$@"
