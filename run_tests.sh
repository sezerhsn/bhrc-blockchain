#!/bin/bash

export BHRC_TEST_MODE=1
echo "🚀 Test ortamı aktif: BHRC_TEST_MODE=1"

pytest "$@"

