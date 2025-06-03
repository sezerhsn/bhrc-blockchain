# BHRC – Geliştirici Dokümantasyonu

## 📦 1. Kurulum Talimatları

### Yerel Geliştirme İçin:

```bash
git clone https://github.com/bhrc-project/bhrc_blockchain.git
cd bhrc_blockchain
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn api_server:app --reload --host 0.0.0.0 --port 80

docker build -t bhrc .
docker run -p 80:80 bhrc

| Endpoint       | Açıklama                         |
| -------------- | -------------------------------- |
| `/chain`       | Zincir bilgisi ve blok erişimi   |
| `/wallet`      | Cüzdan oluşturma ve sorgulama    |
| `/transaction` | İşlem gönderme ve listeleme      |
| `/token`       | Token transfer, onay ve sorgular |
| `/contract`    | Akıllı sözleşme yükleme/çağırma  |
| `/nft`         | NFT oluşturma ve sahiplik takibi |
| `/dao`         | Oylama, teklif oluşturma         |

python wallet_cli.py create         # Yeni cüzdan oluştur
python wallet_cli.py balance        # Cüzdan bakiyesi kontrolü
python wallet_cli.py transfer       # Token gönderimi
python wallet_cli.py history        # İşlem geçmişi

def execute(context):
    sender = context['sender']
    context['storage']['counter'] += 1
    return f"Hello from {sender}"

curl -X POST http://157.245.78.23/contract/deploy -F "code=@contract_example.py"

cd ~/bhrc_blockchain
PYTHONPATH=. pytest bhrc_blockchain/tests

PYTHONPATH=. pytest bhrc_blockchain/tests --cov=bhrc_blockchain --cov-report=term-missing

🧠 6. Entegrasyon Önerileri
Web3.py: REST API'lerle kullanılabilir

React Panel: Uç noktalar frontend’e hazır

DAO sistemleri: Yerleşik yönetişim modülleriyle uyumlu
