"""The share-link builder: encoding correctness and input validation."""

from __future__ import annotations

import uuid as uuid_module
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from app.credential_generator import (
    CredentialError,
    RealityProfile,
    WebSocketProfile,
    build_client_config,
    build_reality_uri,
    build_websocket_uri,
    new_uuid,
)

UUID = "3a6fccfc-0c1b-4138-8dac-d20010ede80c"


@pytest.fixture
def reality_profile():
    return RealityProfile(
        public_key="4Kp94-un_UP_rt5UOgWj9iSZ5Td1xmukCRQMqmaA6zA",
        short_id="0123456789abcdef",
        server_name="www.microsoft.com",
        fingerprint="chrome",
        flow="xtls-rprx-vision",
        spider_x="/",
        network_alias="tcp",
    )


# --------------------------------------------------------------------------- #
# UUID generation
# --------------------------------------------------------------------------- #
def test_new_uuid_is_a_valid_random_uuid4():
    generated = new_uuid()
    parsed = uuid_module.UUID(generated)
    assert parsed.version == 4
    assert str(parsed) == generated


def test_new_uuid_does_not_repeat():
    assert len({new_uuid() for _ in range(500)}) == 500


# --------------------------------------------------------------------------- #
# REALITY links
# --------------------------------------------------------------------------- #
def test_reality_uri_structure(reality_profile):
    uri = build_reality_uri(
        user_uuid=UUID, host="metro.proxy.rlwy.net", port=18423,
        profile=reality_profile, remark="phone-main",
    )
    parsed = urlparse(uri)
    assert parsed.scheme == "vless"
    assert parsed.username == UUID
    assert parsed.hostname == "metro.proxy.rlwy.net"
    assert parsed.port == 18423

    query = parse_qs(parsed.query)
    assert query["type"] == ["tcp"]
    assert query["security"] == ["reality"]
    assert query["encryption"] == ["none"]
    assert query["flow"] == ["xtls-rprx-vision"]
    assert query["fp"] == ["chrome"]
    assert query["pbk"] == ["4Kp94-un_UP_rt5UOgWj9iSZ5Td1xmukCRQMqmaA6zA"]
    assert query["sid"] == ["0123456789abcdef"]
    assert query["sni"] == ["www.microsoft.com"]
    assert query["spx"] == ["/"]
    assert unquote(parsed.fragment) == "phone-main"


def test_reality_uri_respects_raw_network_alias(reality_profile):
    profile = RealityProfile(**{**reality_profile.__dict__, "network_alias": "raw"})
    uri = build_reality_uri(user_uuid=UUID, host="h.example", port=443, profile=profile)
    assert parse_qs(urlparse(uri).query)["type"] == ["raw"]


def test_reality_uri_omits_empty_flow(reality_profile):
    profile = RealityProfile(**{**reality_profile.__dict__, "flow": ""})
    uri = build_reality_uri(user_uuid=UUID, host="h.example", port=443, profile=profile)
    assert "flow=" not in uri


def test_reality_uri_without_remark_has_no_fragment(reality_profile):
    uri = build_reality_uri(user_uuid=UUID, host="h.example", port=443, profile=reality_profile)
    assert "#" not in uri


# --------------------------------------------------------------------------- #
# URL encoding — the classic source of "server works but client cannot import"
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "remark",
    [
        "phone main",
        "phone-main (REALITY)",
        "user#1&2=3",
        "réseau privé",
        "手机",
        "a/b?c=d",
        "100% mine",
        "tab\tand space",
    ],
)
def test_remarks_round_trip_through_percent_encoding(reality_profile, remark):
    uri = build_reality_uri(
        user_uuid=UUID, host="h.example", port=443, profile=reality_profile, remark=remark
    )
    parsed = urlparse(uri)
    assert unquote(parsed.fragment) == remark
    # The fragment must never introduce characters that break the query.
    assert "?" not in parsed.fragment
    assert "&" not in parsed.fragment
    assert " " not in parsed.fragment


def test_spider_x_and_sni_are_encoded(reality_profile):
    profile = RealityProfile(
        **{**reality_profile.__dict__, "spider_x": "/search?q=a b&x=1", "server_name": "www.example.com"}
    )
    uri = build_reality_uri(user_uuid=UUID, host="h.example", port=443, profile=profile)
    query = parse_qs(urlparse(uri).query)
    assert query["spx"] == ["/search?q=a b&x=1"]
    assert query["sni"] == ["www.example.com"]
    # Raw separators must not appear unencoded inside the value.
    raw_query = urlparse(uri).query
    assert "spx=/search?q=a b&x=1" not in raw_query


def test_websocket_path_reserved_characters_are_encoded():
    uri = build_websocket_uri(
        user_uuid=UUID, host="app.up.railway.app", port=443,
        profile=WebSocketProfile(path="/gateway/8f3c?a=b&c=d", host="app.up.railway.app"),
        remark="ws",
    )
    assert "path=%2Fgateway%2F8f3c%3Fa%3Db%26c%3Dd" in uri
    query = parse_qs(urlparse(uri).query)
    assert query["path"] == ["/gateway/8f3c?a=b&c=d"]
    # The encoded path must not smuggle extra query parameters into the link.
    assert set(query) == {"type", "security", "encryption", "path", "host", "sni", "fp"}
    assert "a" not in query and "c" not in query


def test_websocket_path_with_whitespace_is_rejected():
    # A path containing whitespace is always an operator mistake; failing loudly
    # beats silently issuing a link that no client can use.
    with pytest.raises(CredentialError, match="whitespace"):
        build_websocket_uri(
            user_uuid=UUID, host="app.up.railway.app", port=443,
            profile=WebSocketProfile(path="/gateway/8f3c 1d", host="app.up.railway.app"),
        )


# --------------------------------------------------------------------------- #
# WebSocket links
# --------------------------------------------------------------------------- #
def test_websocket_uri_structure():
    uri = build_websocket_uri(
        user_uuid=UUID, host="app.up.railway.app", port=443,
        profile=WebSocketProfile(path="/gateway/abc123", host="app.up.railway.app"),
        remark="phone (WS)",
    )
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    assert parsed.port == 443
    assert query["type"] == ["ws"]
    assert query["security"] == ["tls"]
    assert query["encryption"] == ["none"]
    assert query["host"] == ["app.up.railway.app"]
    assert query["sni"] == ["app.up.railway.app"]
    assert query["path"] == ["/gateway/abc123"]
    # XTLS Vision is invalid over WebSocket and must never be emitted.
    assert "flow" not in query


def test_websocket_path_gets_a_leading_slash():
    uri = build_websocket_uri(
        user_uuid=UUID, host="h.example", port=443,
        profile=WebSocketProfile(path="gateway/x", host="h.example"),
    )
    assert parse_qs(urlparse(uri).query)["path"] == ["/gateway/x"]


# --------------------------------------------------------------------------- #
# validation — never emit a malformed link
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_uuid", ["", "not-a-uuid", "12345", None, "3a6fccfc-0c1b-4138-8dac"])
def test_invalid_uuid_is_rejected(reality_profile, bad_uuid):
    with pytest.raises(CredentialError):
        build_reality_uri(user_uuid=bad_uuid, host="h.example", port=443, profile=reality_profile)


@pytest.mark.parametrize("bad_port", [0, -1, 65536, "abc", None, True])
def test_invalid_port_is_rejected(reality_profile, bad_port):
    with pytest.raises(CredentialError):
        build_reality_uri(user_uuid=UUID, host="h.example", port=bad_port, profile=reality_profile)


@pytest.mark.parametrize("bad_host", ["", "   ", "http://h.example", "h.example/path", "has space"])
def test_invalid_host_is_rejected(reality_profile, bad_host):
    with pytest.raises(CredentialError):
        build_reality_uri(user_uuid=UUID, host=bad_host, port=443, profile=reality_profile)


def test_missing_public_key_is_rejected(reality_profile):
    profile = RealityProfile(**{**reality_profile.__dict__, "public_key": ""})
    with pytest.raises(CredentialError, match="public key"):
        build_reality_uri(user_uuid=UUID, host="h.example", port=443, profile=profile)


def test_unsupported_flow_is_rejected(reality_profile):
    profile = RealityProfile(**{**reality_profile.__dict__, "flow": "xtls-rprx-direct"})
    with pytest.raises(CredentialError, match="flow"):
        build_reality_uri(user_uuid=UUID, host="h.example", port=443, profile=profile)


def test_ipv6_host_is_bracketed(reality_profile):
    uri = build_reality_uri(
        user_uuid=UUID, host="2606:4700:4700::1111", port=443, profile=reality_profile
    )
    assert "@[2606:4700:4700::1111]:443" in uri
    assert urlparse(uri).port == 443


# --------------------------------------------------------------------------- #
# JSON export
# --------------------------------------------------------------------------- #
def test_client_config_for_reality(reality_profile):
    config = build_client_config(
        user_uuid=UUID, host="metro.proxy.rlwy.net", port=18423,
        profile=reality_profile, remark="phone",
    )
    outbound = config["outbounds"][0]
    assert outbound["protocol"] == "vless"
    vnext = outbound["settings"]["vnext"][0]
    assert vnext["address"] == "metro.proxy.rlwy.net"
    assert vnext["port"] == 18423
    assert vnext["users"][0]["id"] == UUID
    assert vnext["users"][0]["flow"] == "xtls-rprx-vision"
    assert outbound["streamSettings"]["security"] == "reality"
    assert outbound["streamSettings"]["realitySettings"]["publicKey"] == reality_profile.public_key
    assert "privateKey" not in str(config)


def test_client_config_for_websocket_has_no_flow():
    config = build_client_config(
        user_uuid=UUID, host="app.up.railway.app", port=443,
        profile=WebSocketProfile(path="/gateway/abc", host="app.up.railway.app"),
    )
    user = config["outbounds"][0]["settings"]["vnext"][0]["users"][0]
    assert "flow" not in user
    assert config["outbounds"][0]["streamSettings"]["network"] == "ws"
