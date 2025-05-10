# Behind The Random Coin (BHRC)

BHRC, Python tabanlı, modüler mimariye sahip bir blockchain uygulamasıdır.  
Peer-to-peer ağı, cüzdan yönetimi, token işlemleri ve blok madenciliği desteklenir.

## 🚀 Kurulum

```bash
git clone <repo-url>
cd bhrc_blockchain
pip install -r requirements.txt

## 🧪 Testler

make test        # Tüm testleri çalıştır
make coverage    # Kapsamı ölç
make clean       # Test kalıntılarını temizle

## 🌐 API

uvicorn api_server:app --reload --host 0.0.0.0 --port 8000

## 📦 Modüller

core/: zincir, blok, işlem ve cüzdan mantığı

network/: p2p haberleşme

database/: SQLite veri yönetimi

tests/: pytest tabanlı testler

## 🛠 Geliştirici Notu

Bu proje DigitalOcean VPS üzerinde çalışmak üzere optimize edilmiştir.
İstemci tarafı (explorer ve wallet) için frontend entegrasyonu yakında gelecektir.


---

🧩 Bunlar tamamlandıysa sıradaki adım frontend (blok explorer) veya test.sh gibi otomatik terminal scripti olabilir. Hazırsan geçelim mi?

