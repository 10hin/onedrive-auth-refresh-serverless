#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

terraform -chdir=infra/ init
terraform -chdir=infra/ validate
terraform -chdir=infra/ fmt
terraform -chdir=infra/ plan -out plan.out
