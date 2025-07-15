import time

def evaluate_contract(tx: dict) -> bool:
    """
    Mini DSL yorumlayıcı - Zaman tabanlı script'leri işler.
    Desteklenen script formatları:
      - if now > <timestamp> then allow/deny
      - if now < <timestamp> then allow/deny
      - if now >= x and now < y then allow/deny
      - if true then allow, if false then deny
      - Satır başı '#' yorumları yok sayılır
    """
    script = tx.get("script", "").strip().lower()
    context = tx.get("context", {})
    context["now"] = int(time.time())
    if not script:
        return False

    script = "\n".join([line for line in script.splitlines() if not line.strip().startswith("#")])
    script = script.strip()

    if not script.startswith("if ") or " then " not in script:
        return False

    try:
        condition_part, action_part = script.split(" then ", 1)
        action = action_part.strip()

        if action not in ("allow", "deny"):
            return False

        now_ts = int(time.time())
        condition = condition_part[3:].strip()

        if condition == "true":
            result = True
        elif condition == "false":
            result = False
        else:
            result = eval_condition(condition, context)

        if action == "allow":
            return result is True
        else:
            return result is False

    except Exception:
        return False

def eval_condition(expr: str, context: dict) -> bool:
    try:
        allowed_names = {
            k: v for k, v in context.items()
            if isinstance(v, (int, float, bool, str, list))
        }
        allowed_names["true"] = True
        allowed_names["false"] = False
        return eval(expr, {"__builtins__": None}, allowed_names)
    except Exception:
        return False

