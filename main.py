import base64
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List

import requests
from loguru import logger

_STUB_TAG_MARKERS = (
    "app not supported",
    "not supported",
    "limit of devices",
    "device limit",
    "devices reached",
    "subscription expired",
    "expired",
    "no access",
    "access denied",
    "blocked",
)
_TAG_SANITIZE_RE = re.compile(r"[^\x20-\x7E]+")
_TAG_SPACES_RE = re.compile(r"\s+")


class XraySubscriptionParser:
    """Parser for Xray subscription links (VLESS URI) to outbound configuration"""

    def __init__(self, uri: str):
        self.uri = uri.strip()
        self.parsed = None
        self.config = None

    def _sanitize_tag(self, tag: str) -> str:
        """Keeps printable ASCII, replaces whitespace runs with '_'."""
        if not tag:
            return ""
        cleaned = _TAG_SANITIZE_RE.sub("", tag).strip()
        return re.sub(r"\s+", "_", cleaned).strip("_")

    def parse(self) -> Dict[str, Any]:
        """Parses URI and returns outbound configuration"""

        if not self.uri.startswith("vless://"):
            raise ValueError("Only VLESS URIs are supported")

        # Remove protocol prefix
        source_uri = self.uri[8:]

        # Extract fragment (tag) — everything after the first '#'
        tag = None
        if "#" in source_uri:
            uri_without_protocol, tag = source_uri.split("#", 1)
        else:
            uri_without_protocol = source_uri

        if "@" not in uri_without_protocol:
            raise ValueError("Invalid URI format: missing @")

        before_at, after_at = uri_without_protocol.split("@", 1)
        uuid = before_at

        # Split address:port and parameters
        if "?" in after_at:
            address_port, query_string = after_at.split("?", 1)
            query_params = urllib.parse.parse_qs(query_string)
            params = {k: v[0] if v else "" for k, v in query_params.items()}
        else:
            address_port = after_at
            params = {}

        # Split address and port (with IPv6 in brackets support)
        if ":" in address_port:
            if address_port.startswith("["):
                end_bracket = address_port.index("]")
                address = address_port[1:end_bracket]
                port_str = address_port[end_bracket + 2 :]  # skip ']:'
                if not port_str:
                    raise ValueError("Port not specified")
                port = int(port_str)
            else:
                parts = address_port.rsplit(":", 1)
                if len(parts) != 2:
                    raise ValueError("Invalid address:port format")
                address = parts[0]
                port = int(parts[1])
        else:
            raise ValueError("Port not specified")

        self.parsed = {
            "uuid": uuid,
            "address": address,
            "port": port,
            "params": params,
            "tag": tag,
        }

        self.config = self._build_outbound()
        return self.config

    def _build_outbound(self) -> Dict[str, Any]:
        if not self.parsed:
            raise ValueError("Call parse() first")

        data = self.parsed
        params = data["params"]

        transport_type = params.get("type", "raw")
        if transport_type == "tcp":
            transport_type = "raw"

        outbound: Dict[str, Any] = {
            "protocol": "vless",
            "settings": {
                "address": data["address"],
                "port": data["port"],
                "id": data["uuid"],
                "encryption": params.get("encryption", "none"),
                "flow": params.get("flow", ""),
            },
            "streamSettings": {
                "network": transport_type,
                "security": params.get("security", "none"),
            },
        }

        # Tag handling (supports URIs with two '#')
        if data["tag"]:
            raw_tag = data["tag"]
            if "#" in raw_tag:
                logger.warning(
                    "Multiple '#' characters in tag '{}'. Taking last part.",
                    raw_tag,
                )
                raw_tag = raw_tag.split("#")[-1]
            cleaned = self._sanitize_tag(urllib.parse.unquote(raw_tag))
            if cleaned:
                outbound["tag"] = cleaned

        network = outbound["streamSettings"]["network"]

        if network == "ws":
            ws_settings = {}
            if "path" in params:
                ws_settings["path"] = urllib.parse.unquote(params["path"])
            if "host" in params:
                ws_settings["headers"] = {"Host": params["host"]}
            if ws_settings:
                outbound["streamSettings"]["wsSettings"] = ws_settings

        elif network == "xhttp":
            xhttp_settings = {}
            if "path" in params:
                xhttp_settings["path"] = urllib.parse.unquote(params["path"])
            if "host" in params:
                xhttp_settings["host"] = params["host"]
            if "mode" in params:
                xhttp_settings["mode"] = params["mode"]
            if "extra" in params:
                try:
                    xhttp_settings["extra"] = json.loads(params["extra"])
                except json.JSONDecodeError as e:
                    logger.warning(
                        "Cannot parse 'extra' JSON for '{}': {}",
                        data["address"],
                        e,
                    )
            if xhttp_settings:
                outbound["streamSettings"]["xhttpSettings"] = xhttp_settings

        elif network == "grpc":
            grpc_settings = {}
            if "path" in params:
                grpc_settings["serviceName"] = urllib.parse.unquote(
                    params["path"]
                )
            if "mode" in params:
                grpc_settings["multiMode"] = params["mode"].lower() == "multi"
            if grpc_settings:
                outbound["streamSettings"]["grpcSettings"] = grpc_settings

        elif network == "quic":
            quic_settings = {}
            if "headerType" in params:
                quic_settings["header"] = {"type": params["headerType"]}
            if "quicSecurity" in params:
                quic_settings["security"] = params["quicSecurity"]
            if "key" in params:
                quic_settings["key"] = params["key"]
            if quic_settings:
                outbound["streamSettings"]["quicSettings"] = quic_settings

        # Security settings
        security = outbound["streamSettings"]["security"]

        if security == "reality":
            reality_settings = {}
            if "sni" in params:
                reality_settings["serverName"] = params["sni"]
            elif "serverName" in params:
                reality_settings["serverName"] = params["serverName"]

            if "fp" in params:
                reality_settings["fingerprint"] = params["fp"]
            elif "fingerprint" in params:
                reality_settings["fingerprint"] = params["fingerprint"]

            if "pbk" in params:
                reality_settings["password"] = params["pbk"]
            elif "publicKey" in params:
                reality_settings["password"] = params["publicKey"]

            if "sid" in params:
                reality_settings["shortId"] = params["sid"]
            elif "shortId" in params:
                reality_settings["shortId"] = params["shortId"]

            if reality_settings:
                outbound["streamSettings"][
                    "realitySettings"
                ] = reality_settings

        elif security == "tls":
            tls_settings = {}
            if "sni" in params:
                tls_settings["serverName"] = params["sni"]
            elif "serverName" in params:
                tls_settings["serverName"] = params["serverName"]

            if "fp" in params:
                tls_settings["fingerprint"] = params["fp"]
            elif "fingerprint" in params:
                tls_settings["fingerprint"] = params["fingerprint"]

            if "alpn" in params:
                tls_settings["alpn"] = params["alpn"].split(",")

            if "allowInsecure" in params:
                tls_settings["allowInsecure"] = (
                    params["allowInsecure"].lower() == "true"
                )

            if tls_settings:
                outbound["streamSettings"]["tlsSettings"] = tls_settings

        # Mux settings
        if "mux" in params and params["mux"].lower() == "true":
            mux_settings = {"enabled": True}
            if "xudp" in params and params["xudp"].lower() == "true":
                mux_settings["xudpConcurrency"] = int(
                    params.get("xudpConcurrency", 8)
                )
                mux_settings["xudpProxyUDP443"] = params.get(
                    "xudpProxyUDP443", "reject"
                )
            outbound["mux"] = mux_settings

        return outbound

    def to_json(self, indent: int = 2, compact: bool = False) -> str:
        if self.config is None:
            raise RuntimeError("Call parse() first")
        if compact:
            return json.dumps(self.config, separators=(",", ":"))
        return json.dumps(self.config, indent=indent, ensure_ascii=False)


def is_stub_outbound(outbound: Dict[str, Any]) -> bool:
    """Detects placeholder outbounds returned by misbehaving subscriptions."""
    settings = outbound.get("settings", {})
    address = settings.get("address", "")
    port = settings.get("port")
    uuid = settings.get("id", "")

    if address in ("0.0.0.0", "127.0.0.1", "::") and port == 1:
        return True
    if uuid == "00000000-0000-0000-0000-000000000000":
        return True

    tag = (outbound.get("tag") or "").lower()
    if any(marker in tag for marker in _STUB_TAG_MARKERS):
        return True

    return False


def get_vless_urls(sub_url: str) -> List[str]:
    """Returns a list of VLESS URIs from a subscription URL or a raw URI."""
    if sub_url.startswith("vless://"):
        return [sub_url]

    resp = requests.get(
        sub_url,
        timeout=15,
        headers={
            "User-Agent": "Happ/3.13.0",
            "X-Device-Os": "Android",
            "X-Device-Locale": "ru",
            "X-Device-Model": "ELP-NX1",
            "X-Ver-Os": "15",
            "Accept-Encoding": "gzip",
            "X-Hwid": "74jf74nf8f4jr5je",
        },
    )
    resp.raise_for_status()
    raw = resp.text.strip()

    # Decode if base64
    try:
        decoded = base64.b64decode(raw).decode("utf-8")
    except Exception:
        decoded = raw

    return [
        line.strip()
        for line in decoded.splitlines()
        if line.startswith("vless://")
    ]


def get_outbounds_section(vless_uris: List[str]) -> List[Dict[str, Any]]:
    """
    Parses a flat list of VLESS URIs into outbound configurations.
    """
    outbounds: List[Dict[str, Any]] = [
        {"tag": "DIRECT", "protocol": "freedom", "settings": {}}
    ]
    unique_tags = set()

    for uri in vless_uris:
        try:
            parser = XraySubscriptionParser(uri)
            outbound = parser.parse()
        except Exception as e:
            logger.error("Error parsing URI '{}...': {}", uri[:50], e)
            continue

        if is_stub_outbound(outbound):
            logger.warning(
                "Skipping stub outbound (address={}, port={}, tag='{}'). "
                "The subscription may require a specific User-Agent.",
                outbound["settings"].get("address"),
                outbound["settings"].get("port"),
                outbound.get("tag"),
            )
            continue

        tag = outbound.get("tag") or outbound["settings"]["address"]

        if tag in unique_tags:
            base = tag
            counter = 1
            while f"{base}_{counter}" in unique_tags:
                counter += 1
            tag = f"{base}_{counter}"
            logger.debug("Duplicated tag '{}' renamed to '{}'.", base, tag)

        outbound["tag"] = tag
        unique_tags.add(tag)
        outbounds.append(outbound)

    return outbounds


def main() -> int:
    input_file = Path("subscriptions.txt")
    output_file = Path("xray_config.json")

    try:
        subscriptions_list = input_file.read_text(
            encoding="utf-8"
        ).splitlines()
    except FileNotFoundError:
        logger.error("File '{}' does not exist.", input_file)
        return 1
    except OSError as e:
        logger.error("Cannot read '{}': {}", input_file, e)
        return 1

    subscriptions_list = [s.strip() for s in subscriptions_list if s.strip()]

    if not subscriptions_list:
        logger.warning("File '{}' is empty. Nothing to do.", input_file)
        return 0

    vless_uris: List[str] = []
    for line in subscriptions_list:
        try:
            vless_uris.extend(get_vless_urls(line))
        except requests.RequestException as e:
            logger.error("Network error for '{}...': {}", line[:50], e)
        except Exception as e:
            logger.error("Failed to fetch '{}...': {}", line[:50], e)

    if not vless_uris:
        logger.error("No VLESS URIs collected from subscriptions.")
        return 2

    outbounds = get_outbounds_section(vless_uris)

    tmp_file = output_file.with_suffix(output_file.suffix + ".tmp")
    try:
        with tmp_file.open("w", encoding="utf-8") as f:
            json.dump(outbounds, f, indent=2, ensure_ascii=False)
        tmp_file.replace(output_file)
    except (OSError, TypeError, ValueError) as e:
        logger.exception("Failed to write '{}': {}", output_file, e)
        tmp_file.unlink(missing_ok=True)
        return 3

    logger.info(
        "File '{}' has been written ({} outbounds).",
        output_file,
        len(outbounds),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
