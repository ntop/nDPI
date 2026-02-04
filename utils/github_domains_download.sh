#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1

DEST_GITHUB=../src/lib/inc_generated/ndpi_domains_github_match.c.inc
DEST_GITHUB_COPILOT=../src/lib/inc_generated/ndpi_domains_github_copilot_match.c.inc
DEST_GITHUB_PACKAGES=../src/lib/inc_generated/ndpi_domains_github_packages_match.c.inc
DEST_GITHUB_ACTIONS=../src/lib/inc_generated/ndpi_domains_github_actions_match.c.inc

LIST_GITHUB=/tmp/github.list
LIST_GITHUB_COPILOT=/tmp/github.copilot.list
LIST_GITHUB_PACKAGES=/tmp/github.packages.list
LIST_GITHUB_ACTIONS=/tmp/github.actions.list

echo "(1) Processing domains..."

./github_domain.py "website" > $LIST_GITHUB
./github_domain.py "copilot" > $LIST_GITHUB_COPILOT
./github_domain.py "packages" > $LIST_GITHUB_PACKAGES
./github_domain.py "actions" > $LIST_GITHUB_ACTIONS

./domains2list.py $LIST_GITHUB "Github" NDPI_PROTOCOL_GITHUB NDPI_PROTOCOL_CATEGORY_COLLABORATIVE NDPI_PROTOCOL_ACCEPTABLE > $DEST_GITHUB
./domains2list.py $LIST_GITHUB_COPILOT "GithubCopilot" NDPI_PROTOCOL_GITHUB_COPILOT NDPI_PROTOCOL_CATEGORY_ARTIFICIAL_INTELLIGENCE NDPI_PROTOCOL_ACCEPTABLE > $DEST_GITHUB_COPILOT
./domains2list.py $LIST_GITHUB_PACKAGES "GithubPackages" NDPI_PROTOCOL_GITHUB_PACKAGES NDPI_PROTOCOL_CATEGORY_HOSTING NDPI_PROTOCOL_ACCEPTABLE > $DEST_GITHUB_PACKAGES
./domains2list.py $LIST_GITHUB_ACTIONS "GithubActions" NDPI_PROTOCOL_GITHUB_ACTIONS NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_GITHUB_ACTIONS

rm -f $LIST_GITHUB $LIST_GITHUB_COPILOT $LIST_GITHUB_PACKAGES $LIST_GITHUB_ACTIONS

echo "(3) Github domains are available in $DEST_GITHUB, $DEST_GITHUB_COPILOT, $DEST_GITHUB_PACKAGES, $DEST_GITHUB_ACTIONS"
exit 0
