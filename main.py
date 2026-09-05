import base64
import json
import re
import urllib.parse
from typing import Any, Dict

import requests


class XraySubscriptionParser:
    """Parser for Xray subscription links (VLESS URI) to outbound configuration"""

    def __init__(self, uri: str):
        self.uri = uri.strip()
        self.parsed = None
        self.config = None

    def parse(self) -> Dict[str, Any]:
        """Parses URI and returns outbound configuration"""

        if not self.uri.startswith("vless://"):
            raise ValueError("Only VLESS URIs are supported")

        # Remove protocol prefix
        source_uri = self.uri[8:]

        # Extract tag (fragment after #)
        tag = None
        if "#" in source_uri:
            uri_without_protocol, tag = source_uri.split("#", 1)

        # Split into parts before and after @
        if "@" not in uri_without_protocol:
            raise ValueError("Invalid URI format: missing @")

        before_at, after_at = uri_without_protocol.split("@", 1)

        # UUID is everything before @
        uuid = before_at

        # Split address:port and parameters
        if "?" in after_at:
            address_port, query_string = after_at.split("?", 1)
            query_params = urllib.parse.parse_qs(query_string)
            # Convert values to strings (parse_qs returns lists)
            params = {k: v[0] if v else "" for k, v in query_params.items()}
        else:
            address_port = after_at
            params = {}

        # Split address and port
        if ":" in address_port:
            # May be IPv6 in brackets
            if address_port.startswith("["):
                # IPv6 address in brackets: [::1]:443
                end_bracket = address_port.index("]")
                address = address_port[1:end_bracket]
                port_str = address_port[end_bracket + 2 :]  # Skip ]:
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

        # Build configuration
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
        """Builds outbound object from parsed data"""

        if not self.parsed:
            raise ValueError("Call parse() first")

        data = self.parsed
        params = data["params"]

        # Main outbound structure

        transport_type = params.get("type", "raw")
        if params.get("type", "raw") == "tcp":
            transport_type = "raw"

        outbound = {
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

        # Add tag if present
        if data["tag"]:
            outbound["tag"] = data["tag"]
            if "#" in data["tag"]:
                tag_parts_list = data["tag"].split("#")
                print(
                    "WARNING: too many '#' characters in 'tag' parameter. Taking last part."
                )
                outbound["tag"] = tag_parts_list[-1]

        # WebSocket handling
        if outbound["streamSettings"]["network"] == "ws":
            ws_settings = {}
            if "path" in params:
                # Decode path (e.g., %2F -> /)
                ws_settings["path"] = urllib.parse.unquote(params["path"])
            if "host" in params:
                ws_settings["headers"] = {"Host": params["host"]}
            if ws_settings:
                outbound["streamSettings"]["wsSettings"] = ws_settings

        if outbound["streamSettings"]["network"] == "xhttp":
            xhttp_settings = {}
            if "path" in params:
                xhttp_settings["path"] = urllib.parse.unquote(params["path"])
            if "host" in params:
                xhttp_settings["host"] = params["host"]
            if "mode" in params:
                xhttp_settings["mode"] = params["mode"]
            if xhttp_settings:
                outbound["streamSettings"]["xhttpSettings"] = xhttp_settings

        # gRPC handling
        elif outbound["streamSettings"]["network"] == "grpc":
            grpc_settings = {}
            if "path" in params:
                grpc_settings["serviceName"] = urllib.parse.unquote(
                    params["path"]
                )
            if "mode" in params:
                grpc_settings["multiMode"] = params["mode"].lower() == "multi"
            if grpc_settings:
                outbound["streamSettings"]["grpcSettings"] = grpc_settings

        # QUIC handling
        elif outbound["streamSettings"]["network"] == "quic":
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
                alpn_values = params["alpn"].split(",")
                tls_settings["alpn"] = alpn_values

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
        """Returns configuration in JSON format"""
        if not self.config:
            self.parse()

        if compact:
            return json.dumps(self.config, separators=(",", ":"))
        return json.dumps(self.config, indent=indent, ensure_ascii=False)


# Usage example
def get_outbounds_section(subscription_urls_list: list) -> list:
    """
    Parses subscription (list of URIs separated by newlines)
    Returns list of outbound configurations
    """
    outbounds = [{"tag": "DIRECT", "protocol": "freedom", "settings": {}}]

    for uri in subscription_urls_list:
        try:
            print(uri)
            parser = XraySubscriptionParser(uri)
            outbound = parser.parse()
            outbounds.append(outbound)
        except Exception as e:
            print(f"Error parsing URI: {uri[:50]}... - {e}")
            continue

    return outbounds


def get_vless_url(sub_url: str) -> str:
    if sub_url.startswith("vless://"):
        return sub_url
    resp = requests.get(sub_url)
    resp.raise_for_status()
    raw = resp.text.strip()

    # Decode if base64
    try:
        decoded = base64.b64decode(raw).decode("utf-8")
    except Exception:
        decoded = raw

    # Parse every vless:// link to decoded one string by string
    vless_links = [
        line.strip()
        for line in decoded.splitlines()
        if line.startswith("vless://")
    ]
    if not vless_links:
        raise ValueError("No vless links in subscription")

    # Take first link for example (logic can be changed)
    return vless_links[0]


if __name__ == "__main__":
    input_file = "subscription.txt"
    output_file = "xray_config.json"
    with open(input_file, "r") as input_data:
        subscriptions_list = input_data.read().splitlines()

    vless_subs_list = [
        get_vless_url(vless_list) for vless_list in subscriptions_list
    ]

    outbounds = get_outbounds_section(vless_subs_list)

    with open(output_file, "w") as file:
        file.write(json.dumps(outbounds, indent=2, ensure_ascii=False))
    print(f'File "{output_file}" has been written.')
