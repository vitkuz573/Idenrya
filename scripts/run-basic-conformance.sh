#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE_DIR="${SUITE_DIR:-/home/vitaly/openid-conformance-suite}"

CONFIG_PATH="$ROOT_DIR/conformance/oidcc-basic-dynamic-config.json"
OVERRIDE_PATH="$ROOT_DIR/conformance/conformance.override.yml"
CERT_DIR="$ROOT_DIR/conformance/certs"
CERT_PATH="$CERT_DIR/oidcc-provider.pfx"
PUBLISH_DIR="$ROOT_DIR/conformance/publish"
RESULT_ROOT="$ROOT_DIR/conformance/results"
RESULT_DIR="$RESULT_ROOT/$(date +%Y%m%d-%H%M%S)"

mkdir -p "$CERT_DIR" "$RESULT_DIR" "$PUBLISH_DIR"

if [[ ! -d "$SUITE_DIR" ]]; then
  echo "Conformance suite directory not found: $SUITE_DIR" >&2
  exit 1
fi

if ! command -v mvn >/dev/null 2>&1; then
  echo "Installing Maven..."
  sudo apt-get update -y >/dev/null
  sudo apt-get install -y maven >/dev/null
fi

JAVA_VERSION="0"
if command -v javac >/dev/null 2>&1; then
  JAVA_VERSION="$(javac -version 2>&1 | awk '{print $2}' | cut -d. -f1)"
fi

if [[ "$JAVA_VERSION" -lt 17 ]]; then
  echo "Installing OpenJDK JDK..."
  sudo apt-get update -y >/dev/null
  sudo apt-get install -y openjdk-21-jdk >/dev/null
  export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

if python3 -c 'import httpx, pyparsing' >/dev/null 2>&1; then
  echo "Python dependencies already available."
else
  echo "Installing Python dependencies for run-test-plan.py..."
  if python3 -m pip --version >/dev/null 2>&1; then
    python3 -m pip install -r "$SUITE_DIR/scripts/requirements.txt" >/dev/null
  else
    sudo apt-get update -y >/dev/null
    sudo apt-get install -y python3-httpx python3-pyparsing >/dev/null
  fi
fi

if [[ ! -f "$SUITE_DIR/target/fapi-test-suite.jar" ]]; then
  echo "Building OpenID conformance suite (first run)..."
  (
    cd "$SUITE_DIR"
    mvn package
  )
fi

echo "Preparing HTTPS certificate for oidcc-provider..."
openssl pkcs12 -export \
  -out "$CERT_PATH" \
  -inkey "$SUITE_DIR/.gitlab-ci/local-provider.key" \
  -in "$SUITE_DIR/.gitlab-ci/local-provider-oidcc.crt" \
  -password pass:oidcc-provider >/dev/null

echo "Publishing Idenrya provider..."
dotnet publish "$ROOT_DIR/Idenrya.Server/Idenrya.Server.csproj" -c Release -o "$PUBLISH_DIR" >/dev/null

export IDENRYA_CONFORMANCE_DIR="$ROOT_DIR/conformance"
export IDENRYA_CERT_PATH="$CERT_PATH"

echo "Starting conformance stack..."
(
  cd "$SUITE_DIR"
  docker compose \
    -f docker-compose-localtest.yml \
    -f "$OVERRIDE_PATH" \
    down --remove-orphans >/dev/null 2>&1 || true

  docker compose \
    -f docker-compose-localtest.yml \
    -f "$OVERRIDE_PATH" \
    up -d --build mongodb oidcc-provider server nginx
)

echo "Waiting for conformance API..."
for _ in $(seq 1 120); do
  if curl -kfsS "https://localhost:8443/api/runner/available" >/dev/null; then
    break
  fi
  sleep 2
done

if ! curl -kfsS "https://localhost:8443/api/runner/available" >/dev/null; then
  echo "Conformance API did not become ready in time." >&2
  (
    cd "$SUITE_DIR"
    docker compose -f docker-compose-localtest.yml -f "$OVERRIDE_PATH" logs --tail=200
  )
  exit 1
fi

echo "Running OIDC Basic certification plan (dynamic client)..."
(
  cd "$SUITE_DIR"
  CONFORMANCE_SERVER="https://localhost:8443/" \
  CONFORMANCE_SERVER_MTLS="https://localhost:8444/" \
  CONFORMANCE_DEV_MODE=1 \
  python3 scripts/run-test-plan.py \
    --no-parallel \
    --export-dir "$RESULT_DIR" \
    oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] \
    "$CONFIG_PATH"
)

echo "Conformance run finished successfully."
echo "Results exported to: $RESULT_DIR"
