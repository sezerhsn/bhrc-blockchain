import time

def evaluate_contract(tx: dict) -> bool:
    """
    Basit zaman kilitli sözleşme kontrolü.
    """
    script = tx.get("script", "")
    if not script:
        return False

    try:
        if "if now >" in script and "then allow" in script:
            parts = script.split(">")
            timestamp_part = parts[1].split("then")[0].strip()
            target_ts = int(timestamp_part)
            now_ts = int(time.time())
            return now_ts > target_ts
        return False
    except:
        return False

