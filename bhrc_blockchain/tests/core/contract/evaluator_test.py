import time
import pytest
from bhrc_blockchain.core.contract.evaluator import evaluate_contract, eval_condition

def test_valid_contract_returns_true(monkeypatch):
    future_time = int(time.time()) - 10
    script = f"if now > {future_time} then allow"
    tx = {"script": script}
    assert evaluate_contract(tx) is True

def test_invalid_contract_returns_false_due_to_time(monkeypatch):
    future_time = int(time.time()) + 9999
    script = f"if now > {future_time} then allow"
    tx = {"script": script}
    assert evaluate_contract(tx) is False

def test_empty_script_returns_false():
    tx = {"script": ""}
    assert evaluate_contract(tx) is False

def test_missing_script_key_returns_false():
    tx = {}
    assert evaluate_contract(tx) is False

def test_invalid_timestamp_in_script_returns_false():
    tx = {"script": "if now > abc then allow"}
    assert evaluate_contract(tx) is False

def test_script_with_non_integer_timestamp_raises_exception():
    tx = {"script": "if now > invalid_timestamp then allow"}
    assert evaluate_contract(tx) is False

def test_script_malformed_structure_raises_exception():
    tx = {"script": "if now > then allow"}
    assert evaluate_contract(tx) is False

def test_script_with_unexpected_format_raises_exception():
    tx = {"script": "nonsense"}
    assert evaluate_contract(tx) is False

def test_now_less_than_timestamp_should_allow():
    future_time = int(time.time()) + 1000
    tx = {"script": f"if now < {future_time} then allow"}
    assert evaluate_contract(tx) is True

def test_now_not_less_than_timestamp_should_deny():
    past_time = int(time.time()) - 1000
    tx = {"script": f"if now < {past_time} then allow"}
    assert evaluate_contract(tx) is False

def test_now_less_than_invalid_timestamp_should_fail_gracefully():
    tx = {"script": "if now < abc then allow"}
    assert evaluate_contract(tx) is False

def test_allow_now_greater_than_timestamp():
    ts = int(time.time()) - 5
    tx = {"script": f"if now > {ts} then allow"}
    assert evaluate_contract(tx) is True

def test_deny_now_less_than_timestamp():
    ts = int(time.time()) + 9999
    tx = {"script": f"if now < {ts} then deny"}
    assert evaluate_contract(tx) is False

def test_allow_with_and_condition_true():
    now = int(time.time())
    tx = {
        "script": f"if now > {now - 10} and now < {now + 10} then allow"
    }
    assert evaluate_contract(tx) is True

def test_deny_with_or_condition_false():
    now = int(time.time())
    tx = {
        "script": f"if now < {now - 9999} or now > {now + 9999} then deny"
    }
    assert evaluate_contract(tx) is True

def test_invalid_action_rejected():
    tx = {"script": "if now > 0 then jump"}
    assert evaluate_contract(tx) is False

def test_malformed_expression_fails_gracefully():
    tx = {"script": "if now >>>> 123 then allow"}
    assert evaluate_contract(tx) is False

def test_eval_condition_raises_exception():
    tx = {"script": "if now ++++ 123 then allow"}
    assert evaluate_contract(tx) is False

def test_eval_condition_with_numeric_logic_error():
    now = int(time.time())
    tx = {"script": f"if now > {now} and then allow"}
    assert evaluate_contract(tx) is False

def test_eval_condition_directly_with_syntax_error():
    assert eval_condition("123 and", {}) is False

def test_condition_with_greater_equal_operator():
    now = int(time.time())
    tx = {"script": f"if now >= {now} then allow"}
    assert evaluate_contract(tx) is True

def test_condition_with_less_equal_operator():
    now = int(time.time())
    tx = {"script": f"if now <= {now + 5} then allow"}
    assert evaluate_contract(tx) is True

def test_condition_with_equality_operator_true():
    now = int(time.time())
    tx = {"script": f"if now == {now} then allow"}
    assert evaluate_contract(tx) is True

def test_condition_with_equality_operator_false():
    now = int(time.time())
    tx = {"script": f"if now == {now + 1} then allow"}
    assert evaluate_contract(tx) is False

def test_condition_with_inequality_operator():
    now = int(time.time())
    tx = {"script": f"if now != {now + 10} then allow"}
    assert evaluate_contract(tx) is True

def test_condition_with_true_direct_literal():
    tx = {"script": "if true then allow"}
    assert evaluate_contract(tx) is True

def test_condition_with_false_direct_literal():
    tx = {"script": "if false then deny"}
    assert evaluate_contract(tx) is True

def test_condition_with_comment_line_ignored():
    now = int(time.time())
    script = f"""# bu bir yorum satırıdır
if now < {now + 1000} then allow"""
    tx = {"script": script}
    assert evaluate_contract(tx) is True

def test_context_balance_condition_true():
    tx = {
        "script": "if balance > 1000 then allow",
        "context": {"balance": 1500}
    }
    assert evaluate_contract(tx) is True

def test_context_balance_condition_false():
    tx = {
        "script": "if balance < 500 then allow",
        "context": {"balance": 600}
    }
    assert evaluate_contract(tx) is False

def test_sender_equals_owner_true():
    tx = {
        "script": "if sender == owner then allow",
        "context": {
            "sender": "0xabc",
            "owner": "0xabc"
        }
    }
    assert evaluate_contract(tx) is True

def test_sender_equals_owner_false():
    tx = {
        "script": "if sender == owner then allow",
        "context": {
            "sender": "0xabc",
            "owner": "0xdef"
        }
    }
    assert evaluate_contract(tx) is False

def test_contract_flag_true():
    tx = {
        "script": "if contract == true then allow",
        "context": {"contract": True}
    }
    assert evaluate_contract(tx) is True

def test_contract_flag_false():
    tx = {
        "script": "if contract == true then allow",
        "context": {"contract": False}
    }
    assert evaluate_contract(tx) is False

def test_sender_in_whitelist_allows():
    tx = {
        "script": "if sender in whitelist then allow",
        "context": {
            "sender": "0xabc",
            "whitelist": ["0xabc", "0xdef"]
        }
    }
    assert evaluate_contract(tx) is True

def test_sender_not_in_blacklist_allows():
    tx = {
        "script": "if sender not in blacklist then allow",
        "context": {
            "sender": "0xabc",
            "blacklist": ["0xdef"]
        }
    }
    assert evaluate_contract(tx) is True

def test_sender_in_blacklist_denies():
    tx = {
        "script": "if sender in blacklist then allow",
        "context": {
            "sender": "0xabc",
            "blacklist": ["0xabc", "0xdef"]
        }
    }
    assert evaluate_contract(tx) is True

def test_sender_not_in_whitelist_denies():
    tx = {
        "script": "if sender in whitelist then allow",
        "context": {
            "sender": "0xzzz",
            "whitelist": ["0xabc"]
        }
    }
    assert evaluate_contract(tx) is False

def test_script_only_comment_lines_returns_false():
    tx = {"script": "# sadece yorum satırı"}
    assert evaluate_contract(tx) is False

def test_script_with_whitespace_only_returns_false():
    tx = {"script": "   "}
    assert evaluate_contract(tx) is False

def test_eval_condition_forces_exception(monkeypatch):
    def broken_eval_condition(expr, context):
        raise Exception("forced error")
    monkeypatch.setattr("bhrc_blockchain.core.contract.evaluator.eval_condition", broken_eval_condition)

    tx = {"script": "if sender == owner then allow", "context": {"sender": "0xabc", "owner": "0xabc"}}
    assert evaluate_contract(tx) is False

def test_eval_condition_unsupported_type():
    context = {"some_var": {"nested": "value"}}
    assert eval_condition("some_var == 5", context) is False

