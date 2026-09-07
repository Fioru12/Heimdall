import pytest
from core.responder import ActiveResponder, is_protected_ip

def test_is_protected_ip_loopback():
    assert is_protected_ip("127.0.0.1") is True
    assert is_protected_ip("::1") is True
    assert is_protected_ip("localhost") is True
    assert is_protected_ip("127.0.1.1") is True

def test_is_protected_ip_custom_whitelist():
    custom = {"192.168.1.50", "10.0.0.1"}
    assert is_protected_ip("192.168.1.50", custom) is True
    assert is_protected_ip("10.0.0.1", custom) is True
    assert is_protected_ip("203.0.113.195", custom) is False

def test_active_responder_refuses_to_block_protected_ip():
    responder = ActiveResponder(dry_run=True, whitelist=["192.168.1.254"])
    # Localhost must be refused
    assert responder.block_ip("127.0.0.1", reason="Test attack") is False
    # Whitelisted gateway must be refused
    assert responder.block_ip("192.168.1.254", reason="Test attack") is False
    # Normal malicious IP allowed to be blocked
    assert responder.block_ip("198.51.100.22", reason="Brute force") is True

def test_active_responder_rejects_invalid_ip_syntax():
    responder = ActiveResponder(dry_run=True)
    assert responder.block_ip("not_an_ip") is False
    assert responder.block_ip("192.168.1.1; rm -rf /") is False
    assert responder.block_ip("999.999.999.999") is False
    assert responder.block_ip("192.168.1.500") is False

