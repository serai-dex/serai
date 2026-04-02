#!/bin/sh
set -e

# Ensure this is present in the environment
if [ "${SERAI_NAME:?}" = "" ]; then
  echo "\`SERAI_NAME\` environment variable wasn't set"
  exit 1
fi
serai-node --network local --identity "$SERAI_NAME"
