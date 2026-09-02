#!/usr/bin/env bash
# Runtime assertions on the bugwarden container image: the things only running
# it can prove (#202, #225). Two callers, so the set cannot drift between them
# — ci.yml smokes a locally built amd64 image on PRs, release.yml smokes each
# architecture's pushed digest before container-manifest publishes the tag.
#
#   usage: scripts/container-smoke.sh serve|uid|sigterm|policy|shell|ca
#
# One assertion per invocation, so a failure names itself in the job UI.
# `serve` starts the container the `uid` and `sigterm` assertions inspect and
# must run before them; the rest stand alone.
#
#   IMAGE        image to run — a local tag, or a ghcr.io/...@sha256: ref
#   CTR          name for the served container (`ca` also uses "$CTR-ca")
#   RUNNER_TEMP  scratch: the policy bind mount, the bearer token, a rootfs tar
set -euo pipefail

: "${IMAGE:?IMAGE must name the image to smoke}"
: "${CTR:?CTR must name the container to run}"
: "${RUNNER_TEMP:?RUNNER_TEMP must name a writable scratch directory}"

# The policy file and the bearer token are made here rather than handed
# between steps through $GITHUB_ENV, so each assertion below can also run on
# its own.
write_policy() {
  # Deliberately identity-free: a policy consulting created_by_me makes
  # startup preflight GET /rest/whoami, and this container reaches no
  # Bugzilla. 0644 so uid 65532 can read the bind mount.
  cat > "$RUNNER_TEMP/policy.toml" <<'EOF'
default_action = "deny"
EOF
}

# Generated rather than written down: the gate refuses anything under 32
# characters, and a literal would be a secret scanner's problem for no gain.
# Worthless by construction — it guards a server holding no Bugzilla
# credential. Cached in a file so the assertions that run after `serve` present
# the token its container was started with.
bearer_token() {
  [ -s "$RUNNER_TEMP/smoke-token" ] ||
    (umask 077 && openssl rand -hex 32 > "$RUNNER_TEMP/smoke-token")
  cat "$RUNNER_TEMP/smoke-token"
}

smoke_serve() {
  write_policy
  token="$(bearer_token)"
  docker run -d --name "$CTR" \
    -p 127.0.0.1:8000:8000 \
    -v "$RUNNER_TEMP/policy.toml:/etc/bugwarden/policy.toml:ro" \
    -e BUGZILLA_SERVER=https://bugzilla.invalid \
    -e BUGWARDEN_HTTP_TOKEN="$token" \
    "$IMAGE"
  # Nothing here passes --transport, --host or --port, so an answer on
  # the published port is the assertion on the image's ENV block: the
  # CLI's own defaults bind 127.0.0.1, which no port mapping reaches,
  # and a stdio or off-by-one-port default reaches it no better. The
  # `:ro` mount is compose.yaml's, since the guard reads the policy
  # once and nothing may reach it afterwards.
  code=000
  for _ in $(seq 1 100); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$CTR")" != "true" ]; then
      echo "::error::the container exited during startup"
      docker logs "$CTR"
      exit 1
    fi
    code="$(curl -s -o /dev/null -m 2 -w '%{http_code}' -X POST http://127.0.0.1:8000/mcp || true)"
    [ "$code" = "000" ] || break
    sleep 0.2
  done
  # The gate wraps the whole router, so an unauthenticated POST is
  # refused before rmcp sees it: the 401 is both the readiness signal
  # and the proof the door is locked.
  if [ "$code" != "401" ]; then
    echo "::error::an unauthenticated POST /mcp answered $code, expected 401"
    docker logs "$CTR"
    exit 1
  fi
  body="$(curl -sS -m 10 -X POST http://127.0.0.1:8000/mcp \
    -H "Authorization: Bearer $token" \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ci-smoke","version":"1"}}}' || true)"
  # serverInfo names this crate and not the SDK (#53), so the
  # handshake identifies which process answered, not merely that one
  # did.
  if ! grep -qF '"serverInfo"' <<< "$body" || ! grep -qF '"name":"bugwarden"' <<< "$body"; then
    echo "::error::the handshake was not answered by bugwarden: $body"
    docker logs "$CTR"
    exit 1
  fi
}

smoke_uid() {
  # The number, not `docker inspect .Config.User`'s "nonroot:nonroot"
  # name: compose.yaml and the README tell operators to chown the key
  # file and the audit directory to 65532, so a base whose nonroot
  # resolves to a different uid breaks every documented deployment
  # while the name still reads correctly.
  uids="$(docker top "$CTR" -o uid,pid | awk 'NR > 1 { print $1 }' | sort -u)"
  if [ "$uids" != "65532" ]; then
    echo "::error::the container runs as uid '$uids', expected 65532"
    exit 1
  fi
}

smoke_sigterm() {
  # #114: PID 1 gets no default SIGTERM action from the kernel, so a
  # binary listening only for ctrl_c survives `docker stop` until the
  # grace period expires and SIGKILL lands — exit 137, never 0.
  # binary_shutdown.rs pins the handlers in the binary; this is the
  # only thing that runs them at PID 1 in the distroless image.
  start="$(date +%s)"
  docker stop -t 10 "$CTR" > /dev/null
  elapsed="$(( $(date +%s) - start ))"
  status="$(docker inspect -f '{{.State.ExitCode}}' "$CTR")"
  if [ "$status" != "0" ]; then
    echo "::error::the container exited $status on SIGTERM (137 = ignored it and was killed)"
    docker logs "$CTR"
    exit 1
  fi
  # Not binary_shutdown.rs's 5s: `date +%s` quantizes, and a loaded
  # runner has stopped a healthy container in 6s where steady state
  # is under a second. Still inside the 10s grace, past which SIGKILL
  # lands and the exit-code arm above catches it instead.
  if [ "$elapsed" -ge 8 ]; then
    echo "::error::SIGTERM took ${elapsed}s to stop the container"
    exit 1
  fi
}

smoke_policy() {
  # The image presets BUGWARDEN_POLICY precisely so an unmounted
  # /etc/bugwarden/policy.toml is a startup error instead of the
  # binary's allow-all fallback. Both variables below are supplied on
  # purpose: clap rejects a missing --server and the bearer gate
  # resolves before the policy loads, so omitting either would make
  # this exit nonzero for a reason that is not the one under test.
  set +e
  out="$(timeout 30 docker run --rm \
    -e BUGZILLA_SERVER=https://bugzilla.invalid \
    -e BUGWARDEN_HTTP_TOKEN="$(bearer_token)" \
    "$IMAGE" 2>&1)"
  status=$?
  set -e
  echo "$out"
  # Before the exit status, because a container that served instead of
  # refusing is killed by `timeout` and exits nonzero too.
  if grep -qF 'Starting Bugzilla MCP server' <<< "$out"; then
    echo "::error::the image served with no policy mounted"
    exit 1
  fi
  if [ "$status" -eq 0 ]; then
    echo "::error::the image started with no policy mounted"
    exit 1
  fi
  if ! grep -qF 'failed to load guard policy from /etc/bugwarden/policy.toml' <<< "$out"; then
    echo "::error::it refused, but not over the missing policy"
    exit 1
  fi
}

smoke_shell() {
  # Control first: without it a broken --entrypoint or a wrong tag
  # would make the refusals below pass for the wrong reason.
  version="$(docker run --rm --entrypoint /usr/local/bin/bugwarden "$IMAGE" --version)"
  case "$version" in
    'bugwarden '*) ;;
    *)
      echo "::error::--version printed '$version'"
      exit 1
      ;;
  esac
  # A base swapped for a debugging-friendly one (alpine, debian) is
  # the regression this catches; distroless static carries no /bin.
  for sh in /bin/sh /bin/bash; do
    if docker run --rm --entrypoint "$sh" "$IMAGE" -c 'exit 0' 2> /dev/null; then
      echo "::error::$sh runs in the image, so the base is no longer distroless"
      exit 1
    fi
  done
}

smoke_ca() {
  # TLS trust is reqwest -> rustls-platform-verifier ->
  # rustls-native-certs, which reads the distroless base's own
  # SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt unfiltered (unset,
  # it probes the same path first), so the runtime base's bundle is
  # what every Bugzilla call trusts. Nothing above dials TLS —
  # bugzilla.invalid is never reached under the identity-free policy —
  # and what covers the bundle today is an accident: reqwest builds the
  # verifier in Client::build and errors on an empty root store, so a
  # scratch base happens to die at the serve step naming nothing about
  # certificates, while a one-cert stub passes all five (#225).
  bundle=etc/ssl/certs/ca-certificates.crt
  cid="$(docker create "$IMAGE")"
  docker export "$cid" > "$RUNNER_TEMP/rootfs.tar"
  docker rm "$cid" > /dev/null
  if ! tar -xf "$RUNNER_TEMP/rootfs.tar" -C "$RUNNER_TEMP" "$bundle" 2> /dev/null; then
    echo "::error::the image ships no /$bundle"
    exit 1
  fi
  # Decoded, not grepped for BEGIN lines: a truncated or re-encoded
  # bundle keeps those, and rustls-native-certs drops what it cannot
  # parse without erroring. distroless ships 150; the floor only has
  # to sit above a stub.
  subjects="$(openssl crl2pkcs7 -nocrl -certfile "$RUNNER_TEMP/$bundle" \
    | openssl pkcs7 -print_certs -noout)"
  roots="$(grep -c '^subject=' <<< "$subjects" || true)"
  if [ "$roots" -lt 100 ]; then
    echo "::error::/$bundle decodes to $roots certificates, expected at least 100"
    exit 1
  fi
  # Present is not loaded: the check above extracts the file as the
  # runner and reads it with openssl, not as uid 65532 with rustls.
  # An unreadable bundle has already killed the serve step by the time
  # this runs, so what this adds is the control-first pattern of "Ship
  # no shell" — the same command as the masked run below, minus the
  # mask, so that refusal is attributable to the mask and nothing else.
  write_policy  # `serve` already did, unless this assertion is run alone
  docker run -d --name "$CTR-ca" \
    -v "$RUNNER_TEMP/policy.toml:/etc/bugwarden/policy.toml:ro" \
    -e BUGZILLA_SERVER=https://bugzilla.invalid \
    -e BUGWARDEN_HTTP_TOKEN="$(bearer_token)" \
    "$IMAGE" > /dev/null
  for _ in $(seq 1 100); do
    if docker logs "$CTR-ca" 2>&1 | grep -qF 'Starting Bugzilla MCP server'; then
      break
    fi
    sleep 0.2
  done
  logs="$(docker logs "$CTR-ca" 2>&1)"
  docker rm -f "$CTR-ca" > /dev/null
  if ! grep -qF 'Starting Bugzilla MCP server' <<< "$logs"; then
    echo "::error::the image did not start with its own CA bundle in place"
    echo "$logs"
    exit 1
  fi
  # The control for that run. Without it, an image whose trust stopped
  # coming from this directory — SSL_CERT_FILE moved, webpki-roots, a
  # lazily built verifier — would still start, and everything above
  # would be measuring a decoration.
  mkdir -p "$RUNNER_TEMP/no-certs"
  set +e
  out="$(timeout 30 docker run --rm \
    -v "$RUNNER_TEMP/policy.toml:/etc/bugwarden/policy.toml:ro" \
    -v "$RUNNER_TEMP/no-certs:/etc/ssl/certs:ro" \
    -e BUGZILLA_SERVER=https://bugzilla.invalid \
    -e BUGWARDEN_HTTP_TOKEN="$(bearer_token)" \
    "$IMAGE" 2>&1)"
  status=$?
  set -e
  echo "$out"
  # Before the exit status, as in the missing-policy step: a container
  # that served is killed by `timeout` and exits nonzero too.
  if grep -qF 'Starting Bugzilla MCP server' <<< "$out"; then
    echo "::error::the image served with an empty /etc/ssl/certs, so nothing here proves the bundle is used"
    exit 1
  fi
  if [ "$status" -eq 0 ]; then
    echo "::error::the image started with an empty /etc/ssl/certs"
    exit 1
  fi
  if ! grep -qF 'No CA certificates were loaded from the system' <<< "$out"; then
    echo "::error::it refused, but not over the empty CA store (check whether rustls-platform-verifier reworded it)"
    exit 1
  fi
}

case "${1-}" in
  serve) smoke_serve ;;
  uid) smoke_uid ;;
  sigterm) smoke_sigterm ;;
  policy) smoke_policy ;;
  shell) smoke_shell ;;
  ca) smoke_ca ;;
  *)
    echo "usage: ${0##*/} serve|uid|sigterm|policy|shell|ca" >&2
    exit 2
    ;;
esac
