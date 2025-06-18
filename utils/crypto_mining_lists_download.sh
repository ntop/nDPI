#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1

./mining_list_update.py

exit $?