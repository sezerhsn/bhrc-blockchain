print("🔥 token_test_api.py YÜKLENDİ")

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
import sqlite3

app = FastAPI()

@app.post("/token/deploy")
def deploy_token(
    name: str,
    symbol: str,
    total_supply: float,
    decimals: int = 0,
    creator_private_key: str = Query(...)
):
    try:
        conn = sqlite3.connect("bhrc_token.db")
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                symbol TEXT PRIMARY KEY,
                name TEXT,
                decimals INTEGER,
                total_supply REAL,
                creator TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS token_balances (
                address TEXT,
                symbol TEXT,
                balance REAL,
                PRIMARY KEY (address, symbol)
            )
        """)

        # Basit adres üretimi (sadece test amaçlı)
        creator_address = "xBHR" + creator_private_key[:60].ljust(60, "0")

        c.execute("INSERT INTO tokens (symbol, name, decimals, total_supply, creator) VALUES (?, ?, ?, ?, ?)",
                  (symbol, name, decimals, total_supply, creator_address))

        c.execute("INSERT INTO token_balances (address, symbol, balance) VALUES (?, ?, ?)",
                  (creator_address, symbol, total_supply))

        conn.commit()
        conn.close()

        return {"message": f"{symbol} token'ı başarıyla oluşturuldu.", "creator": creator_address}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("token_test_api:app", host="0.0.0.0", port=80)

