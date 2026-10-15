# SPDX-License-Identifier: Apache-2.0
#
# The license map of scripts/check-spdx.sh (sourced by it): the files it checks and the license of each path, first
# match wins. Keep it in sync with LICENSE.md: the scripts, tests and workflows are Apache-2.0; the
# specification documents are covered by LICENSE.md and carry no header.
# shellcheck shell=bash disable=SC2034 # spdx_files is read by check-spdx.sh

spdx_files=('*.sh' '*.mjs' '*.js' '*.ts')

license_for() {
  case "$1" in
    */node_modules/* | node_modules/* | target/*) echo skip ;;
    scripts/* | test/* | .github/*) echo Apache-2.0 ;;
    *) echo unmapped ;;
  esac
}
