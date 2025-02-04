from react_agent.configuration import Configuration


def test_configuration_empty() -> None:
    Configuration.from_runnable_config({})

import pytest
from datetime import datetime
from src.react_agent.tools import parse_sbom, check_eol_dates

@pytest.mark.asyncio
async def test_parse_sbom():
    sbom = '{"frameworks": [{"name": "example-framework", "version": "1.0.0"}]}'
    frameworks = await parse_sbom(sbom)
    assert frameworks == [{"name": "example-framework", "version": "1.0.0"}]

@pytest.mark.asyncio
async def test_check_eol_dates():
    frameworks = [{"name": "example-framework", "version": "1.0.0"}]
    upgrades = await check_eol_dates(frameworks)
    assert upgrades == [{
        "name": "example-framework",
        "current_version": "1.0.0",
        "eol_date": "2023-12-31",
        "suggested_version": "2.0.0",
        "suggested_eol_date": "2025-12-31"
    }]