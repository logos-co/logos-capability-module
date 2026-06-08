#!/usr/bin/env bash
#
# Execute the capability-module doc-test end-to-end and regenerate its Markdown.
#
# Spec run here:
#   - capability-module-composition.test.yaml  two payload modules (a callee and
#                                              a caller that depends on it) run in
#                                              a logoscore whose capability broker
#                                              is built from THIS commit, with one
#                                              module calling the other over IPC
#
# The runner is the shared `doctest` CLI
# (https://github.com/logos-co/logos-doctest), invoked directly via its flake.
# `doctest run` executes every command in a temp directory and asserts on the
# output; `doctest generate` renders each spec to Markdown under outputs/;
# `doctest clean` strips build artifacts so only the generated docs remain.
#
# To run against a local logos-doctest checkout instead of the published flake,
# set DOCTEST, e.g.:  DOCTEST="nix run path:../../logos-doctest --" ./run.sh
#
set -euo pipefail

# Run from this doctests/ directory regardless of where the script is invoked from.
cd "$(dirname "$0")"

# The doctest CLI. Override by exporting DOCTEST (space-separated command).
read -r -a DOCTEST <<< "${DOCTEST:-nix run github:logos-co/logos-doctest --}"
OUTPUT_DIR="./outputs"
SPECS=(
  "capability-module-composition.test.yaml"
)

# Build the doc-test against THIS repo's current commit rather than the latest
# published flake. The spec overrides `logos-capability-module` (in both the
# logos-logoscore-cli root and its logos-liblogos sub-input) with
# `github:logos-co/logos-capability-module{release}`, and the pin below makes
# {release} expand to $COMMIT — so the capability layer the runtime loads is built
# from exactly what's checked out here. Override by exporting COMMIT (e.g. a tag),
# or set COMMIT="" to fall back to latest master.
#
# Note: nix fetches the commit from the GitHub remote, so $COMMIT must be pushed
# to logos-co/logos-capability-module. A local-only / uncommitted HEAD won't
# resolve; export COMMIT="" (or push first) in that case.
COMMIT="${COMMIT-$(git rev-parse HEAD)}"
RELEASE_FOR=()
if [ -n "${COMMIT}" ]; then
  RELEASE_FOR=(--release-for "logos-capability-module=${COMMIT}")
  echo "==> Pinning logos-capability-module to ${COMMIT}"
else
  echo "==> COMMIT empty; building against latest logos-capability-module master"
fi

echo "==> Clearing previous ${OUTPUT_DIR}/"
# A prior run copies module artifacts out of the read-only nix store, so the
# directories land read-only (r-x) too. `rm -rf` can't delete files inside a
# directory it can't write to, so restore write permission first.
if [ -e "${OUTPUT_DIR}" ]; then
  chmod -R u+w "${OUTPUT_DIR}" 2>/dev/null || true
fi
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

for SPEC in "${SPECS[@]}"; do
  name="$(basename "${SPEC%.test.yaml}")"
  # Each spec runs in its OWN workdir under outputs/. A standalone spec uses
  # --output-dir directly as its working tree and leaves read-only nix-store
  # copies under modules/, so giving each spec its own dir keeps reruns clean.
  # The rendered .md is still written flat into outputs/ (matching the
  # .gitignore keep rule).
  spec_out="${OUTPUT_DIR}/${name}"
  mkdir -p "${spec_out}"

  echo "==> Running ${SPEC} into ${spec_out}/"
  # ${RELEASE_FOR[@]+...} guards the expansion so an empty array doesn't trip
  # `set -u` on older bash (e.g. macOS's stock 3.2).
  "${DOCTEST[@]}" run "${SPEC}" \
    --verbose \
    --continue-on-fail \
    ${RELEASE_FOR[@]+"${RELEASE_FOR[@]}"} \
    --output-dir "${spec_out}/"

  echo "==> Generating ${OUTPUT_DIR}/${name}.md"
  "${DOCTEST[@]}" generate "${SPEC}" \
    ${RELEASE_FOR[@]+"${RELEASE_FOR[@]}"} \
    -o "${OUTPUT_DIR}/${name}.md"
done

if [ ! -d "${OUTPUT_DIR}" ]; then
  echo "==> No ${OUTPUT_DIR}/ produced; nothing to clean."
  exit 0
fi

echo "==> Cleaning build artifacts from ${OUTPUT_DIR}/"
"${DOCTEST[@]}" clean "${OUTPUT_DIR}" --verbose

echo "==> Done. Rendered docs are in ${OUTPUT_DIR}/"
