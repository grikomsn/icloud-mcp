"""Authentication management for iCloud MCP server."""

import base64
from typing import Tuple, Optional
from fastmcp import Context
from fastmcp.server.dependencies import get_http_headers
from .config import config


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


def get_credentials(context: Context) -> Tuple[str, str]:
    """Extract iCloud credentials from HTTP headers.

    Authentication priority:
    1. Authorization header with Bearer token (base64 encoded email:password)
    2. X-Apple-Email and X-Apple-App-Specific-Password headers
    3. Environment variables (ICLOUD_EMAIL, ICLOUD_APP_SPECIFIC_PASSWORD)
    """

    # Get HTTP headers using FastMCP's dependency function
    headers = get_http_headers()
    print(f"[AUTH DEBUG] Headers retrieved: {list(headers.keys())}")

    email: Optional[str] = None
    password: Optional[str] = None

    # Priority 1: Check for Authorization header with Bearer token
    auth_header = headers.get("authorization") or headers.get("Authorization")
    if auth_header:
        print("[AUTH DEBUG] Authorization header found")
        try:
            # Expected format: "Bearer <base64_token>"
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                token = parts[1]
                # Decode base64 token
                decoded = base64.b64decode(token).decode("utf-8")
                # Expected format: "email:app_password"
                if ":" in decoded:
                    email, password = decoded.split(":", 1)
                    print(
                        f"[AUTH DEBUG] Credentials extracted from Bearer token - email: {email}"
                    )
                else:
                    print(
                        "[AUTH DEBUG] Invalid Bearer token format - missing colon separator"
                    )
            else:
                print("[AUTH DEBUG] Invalid Authorization header format")
        except (ValueError, base64.binascii.Error) as e:
            print(f"[AUTH DEBUG] Failed to decode Bearer token: {e}")

    # Priority 2: Check for X-Apple-* headers
    if not email:
        email = headers.get("x-apple-email") or headers.get("X-Apple-Email")
        print(f"[AUTH DEBUG] Email from X-Apple-Email header: {email}")
    if not password:
        password = headers.get("x-apple-app-specific-password") or headers.get(
            "X-Apple-App-Specific-Password"
        )
        print(
            f"[AUTH DEBUG] Password from X-Apple-App-Specific-Password header: {'***' if password else None}"
        )

    # Priority 3: Fallback to environment variables
    if not email:
        email = config.FALLBACK_EMAIL
        print(f"[AUTH DEBUG] Using fallback email from environment: {email}")
    if not password:
        password = config.FALLBACK_PASSWORD
        print(
            f"[AUTH DEBUG] Using fallback password from environment: {'***' if password else None}"
        )

    # Validate credentials
    if not email or not password:
        print(
            f"[AUTH DEBUG] AUTHENTICATION FAILED - email: {email}, password: {'***' if password else None}"
        )
        raise AuthenticationError(
            "Authentication required. Provide credentials via:\n"
            "1. Authorization header (Bearer <base64(email:password)>), or\n"
            "2. Headers (X-Apple-Email, X-Apple-App-Specific-Password), or\n"
            "3. Environment variables (ICLOUD_EMAIL, ICLOUD_APP_SPECIFIC_PASSWORD)"
        )

    print(f"[AUTH DEBUG] Authentication successful for email: {email}")
    return email, password


def require_auth(context: Context) -> Tuple[str, str]:
    """Decorator-friendly authentication check."""
    print("[AUTH DEBUG] ========== require_auth CALLED ==========")
    print(f"[AUTH DEBUG] Context received: {context}")
    try:
        result = get_credentials(context)
        print("[AUTH DEBUG] ========== require_auth SUCCESS ==========")
        return result
    except Exception as e:
        print(f"[AUTH DEBUG] ========== require_auth FAILED: {e} ==========")
        raise
