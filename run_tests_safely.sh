#!/bin/bash
echo "📦 Tüm test dosyaları sırayla çalıştırılıyor..."

for file in /root/bhrc_blockchain/bhrc_blockchain/tests/*_test.py; do
  echo "🧪 Çalıştırılıyor: $file"
  PYTHONPATH=/root/bhrc_blockchain pytest "$file" --maxfail=3 --tb=short --disable-warnings || echo "❌ Hata: $file"
  echo "--------------------------------------------"
done

echo "✅ Tüm test çalışmaları tamamlandı."

