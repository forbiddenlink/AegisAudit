from typing import Dict, Any

DEFAULT_POLICY: Dict[str, Any] = {
    "required_headers": {
        "strict-transport-security": {
            "min_max_age": 15552000,  # 180 days
            "include_subdomains": True
        },
        "content-security-policy": {
            "required": True
        },
        "x-content-type-options": {
            "value": "nosniff"
        },
        "referrer-policy": {
            "required": True
        },
        "permissions-policy": {
            "required": True
        }
    },
    "banned_headers": [
        "server",
        "x-powered-by",
        "x-aspnet-version"
    ]
}
