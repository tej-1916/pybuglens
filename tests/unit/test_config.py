"""Unit tests for configuration management."""

from bug_detector.core.config import Settings, get_settings


class TestSettings:
    """Test suite for application Settings."""

    def test_default_settings(self) -> None:
        """Verify default configuration attributes."""
        settings = Settings()
        assert settings.app_name == "AI-Powered Bug Detection System"
        assert settings.app_version == "0.1.0"
        assert settings.environment == "development"
        assert settings.debug is False
        assert settings.host == "127.0.0.1"
        assert settings.port == 8000
        assert settings.max_code_size_bytes == 100 * 1024
        assert settings.max_code_lines == 2000
        assert settings.demo_mode is False
        assert settings.rate_limit_per_minute == 60

    def test_is_ai_available_flag(self) -> None:
        """Test AI availability conditions based on API key and demo mode."""
        # Case 1: No API key
        s1 = Settings(openai_api_key=None, demo_mode=False)
        assert s1.is_ai_available is False

        # Case 2: Whitespace/empty API key
        s2 = Settings(openai_api_key="   ", demo_mode=False)
        assert s2.is_ai_available is False

        # Case 3: Valid key, demo mode inactive
        s3 = Settings(openai_api_key="sk-test-mock-key-12345", demo_mode=False)
        assert s3.is_ai_available is True

        # Case 4: Valid key, BUT demo mode active (security guardrail)
        s4 = Settings(openai_api_key="sk-test-mock-key-12345", demo_mode=True)
        assert s4.is_ai_available is False

    def test_get_settings_cached(self) -> None:
        """Verify get_settings returns a singleton cached Settings instance."""
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2
        assert isinstance(s1, Settings)

    def test_custom_settings_override(self) -> None:
        """Verify custom setting overrides."""
        custom = Settings(
            app_name="Custom Detector",
            port=9000,
            max_code_size_bytes=50000,
            max_code_lines=500,
        )
        assert custom.app_name == "Custom Detector"
        assert custom.port == 9000
        assert custom.max_code_size_bytes == 50000
        assert custom.max_code_lines == 500
