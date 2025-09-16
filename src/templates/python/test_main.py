#!/usr/bin/env python3
"""
Tests for Stoffel MPC application
"""

import pytest
import asyncio
from src.main import main, healthcare_example
from stoffel import StoffelClient


class TestStoffelMPC:

    @pytest.mark.asyncio
    async def test_basic_connection(self):
        """Test that we can create a StoffelClient"""
        client = StoffelClient({
            "nodes": ["http://localhost:9001"],
            "client_id": "test_client",
            "program_id": "test_program"
        })

        # Basic client tests
        assert client is not None
        assert not client.is_ready()  # Should not be ready without connection

        # Note: Actual connection tests require running MPC nodes

    def test_program_configuration(self):
        """Test program configuration"""
        # Test that configuration values are set correctly
        assert True  # Placeholder for program configuration tests

    @pytest.mark.asyncio
    async def test_local_computation(self):
        """Test local computation without MPC network"""
        # This would test the StoffelLang program locally
        # before deploying to MPC network
        assert True  # Placeholder for local execution tests


if __name__ == "__main__":
    pytest.main([__file__])