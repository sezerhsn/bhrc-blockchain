#!/bin/bash

echo "🔍 BHRC Tüm Testler Başlatılıyor..."
cd "$(dirname "$0")"

PYTHONPATH=./bhrc_blockchain coverage run --source=bhrc_blockchain -m pytest bhrc_blockchain/tests

coverage report -m

# 👇 Codecov için XML formatında coverage çıktısı oluştur
coverage xml -o coverage.xml

coverage html

echo "✅ Testler tamamlandı.
📄 coverage.xml (Codecov içindir)
🌐 htmlcov/index.html (Görsel coverage raporu)"

