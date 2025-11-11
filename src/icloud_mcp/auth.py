"""Authentication management for iCloud MCP server."""

import base64
import binascii
from typing import Optional, Tuple

from fastmcp import Context
from fastmcp.server.dependencies import get_http_headers

from .config import config


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


def _extract_bearer_credentials(headers) -> Optional[Tuple[str, str]]:
    """Return credentials derived from an Authorization bearer token, if present."""
    auth_header = headers.get("authorization") or headers.get("Authorization")
    if not auth_header:
        return None

    print("[AUTH DEBUG] Authorization header detected")

    scheme, _, token = auth_header.strip().partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthenticationError(
            "Invalid Authorization header format. Expected `Authorization: Bearer <token>` "
            "per Model Context Protocol authorization spec (2025-06-18)."
        )

    token = token.strip()
    if not token:
        raise AuthenticationError(
            "Missing bearer token. Provide base64 encoded `email:app_password` "
            "per Model Context Protocol authorization spec (2025-06-18)."
        )

    try:
        decoded_bytes = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuthenticationError(
            "Invalid bearer token encoding. Token must be base64 encoded `email:app_password` "
            "per Model Context Protocol authorization spec (2025-06-18)."
        ) from exc

    try:
        decoded_value = decoded_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuthenticationError(
            "Invalid bearer token payload. Token must decode to `email:app_password` "
            "per Model Context Protocol authorization spec (2025-06-18)."
        ) from exc

    if ":" not in decoded_value:
        raise AuthenticationError(
            "Invalid bearer token payload. Expected `email:app_password` before base64 encoding "
            "per Model Context Protocol authorization spec (2025-06-18)."
        )

    email, password = decoded_value.split(":", 1)

    email = email.strip()
    password = password.strip()

    if not email or not password:
        raise AuthenticationError(
            "Invalid bearer token payload. Email and app password must both be non-empty "
            "per Model Context Protocol authorization spec (2025-06-18)."
        )

    print(f"[AUTH DEBUG] Credentials derived from bearer token for email: {email}")
    return email, password


def get_credentials(context: Context) -> Tuple[str, str]:
    """Extract iCloud credentials from Authorization header, custom headers, or environment."""

    # Get HTTP headers using FastMCP's dependency function
    headers = get_http_headers()
    print(f"[AUTH DEBUG] Headers retrieved: {list(headers.keys())}")

    email: Optional[str]
    password: Optional[str]

    # Attempt to derive credentials from Authorization bearer token first
    bearer_credentials = _extract_bearer_credentials(headers)
    if bearer_credentials:
        email, password = bearer_credentials
        print("[AUTH DEBUG] Using credentials provided via bearer token")
    else:
        # Extract credentials from custom headers
        email = headers.get("x-apple-email") or headers.get("X-Apple-Email")
        password = headers.get("x-apple-app-specific-password") or headers.get("X-Apple-App-Specific-Password")

        print(f"[AUTH DEBUG] Email from headers: {email}")
        print(f"[AUTH DEBUG] Password from headers: {'***' if password else None}")

        # Fallback to environment variables when header information is missing
        if not email:
            email = config.FALLBACK_EMAIL
            print(f"[AUTH DEBUG] Using fallback email: {email}")
        if not password:
            password = config.FALLBACK_PASSWORD
            print(f"[AUTH DEBUG] Using fallback password: {'***' if password else None}")

    # Validate credentials
    if not email or not password:
        print(f"[AUTH DEBUG] AUTHENTICATION FAILED - email: {email}, password: {'***' if password else None}")
        raise AuthenticationError(
            "Authentication required. Provide credentials via Authorization bearer token "
            "(`Authorization: Bearer base64(email:app_password)`), custom headers "
            "(X-Apple-Email, X-Apple-App-Specific-Password), or environment variables "
            "(ICLOUD_EMAIL, ICLOUD_APP_SPECIFIC_PASSWORD)."
        )

    print(f"[AUTH DEBUG] Authentication successful for email: {email}")
    return email, password


def require_auth(context: Context) -> Tuple[str, str]:
    """Decorator-friendly authentication check."""
    print("[AUTH DEBUG] ========== require_auth CALLED ==========")
    print(f"[AUTH DEBUG] Context received: {context}")
    try:
        result = get_credentials(context)
        print(f"[AUTH DEBUG] ========== require_auth SUCCESS ==========")
        return result
    except Exception as e:
        print(f"[AUTH DEBUG] ========== require_auth FAILED: {e} ==========")
        raise
