"""Tests for authentication module."""

import base64
from unittest.mock import patch, MagicMock
import pytest

from icloud_mcp.auth import get_credentials, AuthenticationError


class TestAuthentication:
    """Test authentication methods."""

    @patch("icloud_mcp.auth.get_http_headers")
    def test_bearer_token_authentication(self, mock_headers):
        """Test authentication using Authorization Bearer token."""
        # Prepare test credentials
        email = "test@icloud.com"
        password = "test-password"
        credentials = f"{email}:{password}"
        token = base64.b64encode(credentials.encode()).decode()

        # Mock headers with Authorization header
        mock_headers.return_value = {"Authorization": f"Bearer {token}"}

        # Mock context
        context = MagicMock()

        # Test authentication
        result_email, result_password = get_credentials(context)

        assert result_email == email
        assert result_password == password

    @patch("icloud_mcp.auth.get_http_headers")
    def test_bearer_token_lowercase_authorization(self, mock_headers):
        """Test authentication using lowercase 'authorization' header."""
        # Prepare test credentials
        email = "test@icloud.com"
        password = "test-password"
        credentials = f"{email}:{password}"
        token = base64.b64encode(credentials.encode()).decode()

        # Mock headers with lowercase authorization header
        mock_headers.return_value = {"authorization": f"Bearer {token}"}

        # Mock context
        context = MagicMock()

        # Test authentication
        result_email, result_password = get_credentials(context)

        assert result_email == email
        assert result_password == password

    @patch("icloud_mcp.auth.get_http_headers")
    def test_bearer_token_case_insensitive_bearer(self, mock_headers):
        """Test that 'bearer' keyword is case-insensitive."""
        # Prepare test credentials
        email = "test@icloud.com"
        password = "test-password"
        credentials = f"{email}:{password}"
        token = base64.b64encode(credentials.encode()).decode()

        # Mock headers with different bearer cases
        mock_headers.return_value = {"Authorization": f"bearer {token}"}

        # Mock context
        context = MagicMock()

        # Test authentication
        result_email, result_password = get_credentials(context)

        assert result_email == email
        assert result_password == password

    @patch("icloud_mcp.auth.get_http_headers")
    def test_bearer_token_with_colon_in_password(self, mock_headers):
        """Test bearer token with password containing colon."""
        # Prepare test credentials with colon in password
        email = "test@icloud.com"
        password = "test:pass:word"
        credentials = f"{email}:{password}"
        token = base64.b64encode(credentials.encode()).decode()

        # Mock headers
        mock_headers.return_value = {"Authorization": f"Bearer {token}"}

        # Mock context
        context = MagicMock()

        # Test authentication
        result_email, result_password = get_credentials(context)

        assert result_email == email
        assert result_password == password

    @patch("icloud_mcp.auth.get_http_headers")
    def test_x_apple_headers_fallback(self, mock_headers):
        """Test fallback to X-Apple-* headers when Authorization is not present."""
        # Mock headers with X-Apple-* headers
        mock_headers.return_value = {
            "X-Apple-Email": "test@icloud.com",
            "X-Apple-App-Specific-Password": "test-password",
        }

        # Mock context
        context = MagicMock()

        # Test authentication
        result_email, result_password = get_credentials(context)

        assert result_email == "test@icloud.com"
        assert result_password == "test-password"

    @patch("icloud_mcp.auth.get_http_headers")
    def test_x_apple_headers_lowercase(self, mock_headers):
        """Test fallback to lowercase x-apple-* headers."""
        # Mock headers with lowercase headers
        mock_headers.return_value = {
            "x-apple-email": "test@icloud.com",
            "x-apple-app-specific-password": "test-password",
        }

        # Mock context
        context = MagicMock()

        # Test authentication
        result_email, result_password = get_credentials(context)

        assert result_email == "test@icloud.com"
        assert result_password == "test-password"

    @patch("icloud_mcp.auth.get_http_headers")
    @patch("icloud_mcp.auth.config")
    def test_environment_variable_fallback(self, mock_config, mock_headers):
        """Test fallback to environment variables."""
        # Mock empty headers
        mock_headers.return_value = {}

        # Mock config with environment variables
        mock_config.FALLBACK_EMAIL = "env@icloud.com"
        mock_config.FALLBACK_PASSWORD = "env-password"

        # Mock context
        context = MagicMock()

        # Test authentication
        result_email, result_password = get_credentials(context)

        assert result_email == "env@icloud.com"
        assert result_password == "env-password"

    @patch("icloud_mcp.auth.get_http_headers")
    def test_bearer_token_priority_over_x_apple(self, mock_headers):
        """Test that Authorization Bearer token takes priority over X-Apple-* headers."""
        # Prepare bearer token
        email = "bearer@icloud.com"
        password = "bearer-password"
        credentials = f"{email}:{password}"
        token = base64.b64encode(credentials.encode()).decode()

        # Mock headers with both Authorization and X-Apple-* headers
        mock_headers.return_value = {
            "Authorization": f"Bearer {token}",
            "X-Apple-Email": "xapple@icloud.com",
            "X-Apple-App-Specific-Password": "xapple-password",
        }

        # Mock context
        context = MagicMock()

        # Test authentication - should use bearer token
        result_email, result_password = get_credentials(context)

        assert result_email == email
        assert result_password == password

    @patch("icloud_mcp.auth.get_http_headers")
    def test_invalid_bearer_token_format(self, mock_headers):
        """Test authentication fails with invalid bearer token format."""
        # Mock headers with invalid bearer token (not base64)
        mock_headers.return_value = {"Authorization": "Bearer invalid-token-format"}

        # Mock context
        context = MagicMock()

        # Test authentication should fail
        with pytest.raises(AuthenticationError):
            get_credentials(context)

    @patch("icloud_mcp.auth.get_http_headers")
    def test_bearer_token_missing_colon(self, mock_headers):
        """Test authentication fails when bearer token doesn't contain colon."""
        # Create token without colon
        token = base64.b64encode(b"emailonly").decode()

        # Mock headers
        mock_headers.return_value = {"Authorization": f"Bearer {token}"}

        # Mock context
        context = MagicMock()

        # Test authentication should fail
        with pytest.raises(AuthenticationError):
            get_credentials(context)

    @patch("icloud_mcp.auth.get_http_headers")
    def test_no_credentials(self, mock_headers):
        """Test authentication fails when no credentials are provided."""
        # Mock empty headers
        mock_headers.return_value = {}

        # Mock context
        context = MagicMock()

        # Test authentication should fail
        with pytest.raises(AuthenticationError):
            get_credentials(context)

    @patch("icloud_mcp.auth.get_http_headers")
    def test_partial_x_apple_headers_with_env_fallback(self, mock_headers):
        """Test partial X-Apple headers with environment fallback."""
        # Mock headers with only email
        mock_headers.return_value = {"X-Apple-Email": "header@icloud.com"}

        # Set environment variable for password
        with patch("icloud_mcp.auth.config") as mock_config:
            mock_config.FALLBACK_EMAIL = "env@icloud.com"
            mock_config.FALLBACK_PASSWORD = "env-password"

            # Mock context
            context = MagicMock()

            # Test authentication
            result_email, result_password = get_credentials(context)

            # Should use email from header and password from env
            assert result_email == "header@icloud.com"
            assert result_password == "env-password"

    @patch("icloud_mcp.auth.get_http_headers")
    def test_bearer_token_with_special_characters(self, mock_headers):
        """Test bearer token with special characters in email and password."""
        # Prepare test credentials with special characters
        email = "test+tag@icloud.com"
        password = "p@$$w0rd!#%"
        credentials = f"{email}:{password}"
        token = base64.b64encode(credentials.encode()).decode()

        # Mock headers
        mock_headers.return_value = {"Authorization": f"Bearer {token}"}

        # Mock context
        context = MagicMock()

        # Test authentication
        result_email, result_password = get_credentials(context)

        assert result_email == email
        assert result_password == password
