#!/bin/bash

echo "📦 Her test dosyası için ayrı coverage testi başlatılıyor..."
echo "------------------------------------------------------------"

for file in bhrc_blockchain/tests/*_test.py; do
  echo "🧪 Çalıştırılıyor: $file"
  coverage run --branch --source=bhrc_blockchain -m pytest "$file"
  coverage report -m --omit="*/tests/*"
  echo "------------------------------------------------------------"
done

echo "✅ Tüm coverage testleri tamamlandı."

