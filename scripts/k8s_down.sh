#!/usr/bin/env bash
# Delete the local k3d cluster created by scripts/k8s_up.sh, including its volumes.
set -euo pipefail
k3d cluster delete absp
