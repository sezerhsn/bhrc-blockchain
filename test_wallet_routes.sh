#!/bin/bash

# Test ortamı bayrağını aktif et
export BHRC_TEST_MODE=1

echo "🚀 test_wallet_routes_test.py çalıştırılıyor (BHRC_TEST_MODE=1)..."
pytest bhrc_blockchain/tests/api/wallet_routes_test.py

