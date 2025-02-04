import asyncio
import json
from typing import Any, Callable, List, Optional, Dict, cast
from datetime import datetime
import os
import aiohttp
import logging
from dotenv import load_dotenv

from anthropic import APIStatusError
from langchain_community.tools.tavily_search import TavilySearchResults
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import InjectedToolArg
from typing_extensions import Annotated

from react_agent.configuration import Configuration

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def search(
    query: str, *, config: Annotated[RunnableConfig, InjectedToolArg]
) -> Optional[List[Dict[str, Any]]]:
    """Search for general web results.

    This function performs a search using the Tavily search engine, which is designed
    to provide comprehensive, accurate, and trusted results. It's particularly useful
    for answering questions about current events.
    """
    configuration = Configuration.from_runnable_config(config)
    wrapped = TavilySearchResults(max_results=configuration.max_search_results)
    
    max_retries = 5
    for attempt in range(max_retries):
        try:
            result = await wrapped.ainvoke({"query": query})
            return cast(List[Dict[str, Any]], result)
        except APIStatusError as e:
            if 'overloaded_error' in str(e):
                wait_time = 2 ** attempt  # Exponential backoff
                logger.warning(f"API is overloaded. Retrying in {wait_time} seconds...")
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"APIStatusError: {e}")
                raise e
    logger.error("Max retries reached. API is still overloaded.")
    return None

async def fetch_eol_data(framework: str) -> Optional[Dict[str, Any]]:
    """Fetch EOL data from endoflife.date API."""
    url = f"https://endoflife.date/api/{framework}.json"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Fetched EOL data for {framework}: {data}")
                    return data
                else:
                    logger.error(f"Failed to fetch EOL data for {framework}: {response.status}")
                    return None
    except aiohttp.ClientError as e:
        logger.error(f"HTTP request failed: {e}")
        return None

async def parse_sbom(
    sbom: str, *, config: Annotated[RunnableConfig, InjectedToolArg]
) -> Optional[List[Dict[str, Any]]]:
    """Parse the SBOM and extract framework information."""
    logger.info("Parsing SBOM...")
    try:
        sbom_data = json.loads(sbom)
        frameworks = sbom_data.get("components", [])
        if not isinstance(frameworks, list):
            logger.warning("No frameworks found in SBOM.")
            return None
        logger.info(f"Parsed frameworks: {frameworks}")
        return frameworks
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse SBOM: {e}")
        return None

async def check_eol_dates(
    frameworks: List[Dict[str, Any]], *, config: Annotated[RunnableConfig, InjectedToolArg]
) -> Optional[List[Dict[str, Any]]]:
    """Check the EOL dates of the frameworks and suggest upgrades."""
    if not frameworks:
        logger.warning("No frameworks to check.")
        return None

    upgrades = []
    for framework in frameworks:
        name = framework["name"]
        version = framework["version"]
        major_version = version.split('.')[0]  # Extract the major version part
        eol_data = await fetch_eol_data(name)
        if eol_data:
            # Find the version data for the major version
            version_data = next((item for item in eol_data if item["cycle"] == major_version), None)
            if version_data:
                eol_date_str = version_data.get("eol")
                if isinstance(eol_date_str, str):  # Ensure eol_date_str is a string
                    eol_date = datetime.strptime(eol_date_str, "%Y-%m-%d")
                    if eol_date < datetime.now():
                        # Suggest upgrade
                        latest_version = max(eol_data, key=lambda v: datetime.strptime(v["eol"], "%Y-%m-%d") if isinstance(v["eol"], str) else datetime.max)
                        upgrades.append({
                            "name": name,
                            "current_version": version,
                            "eol_date": eol_date_str,
                            "suggested_version": latest_version["cycle"],
                            "suggested_eol_date": latest_version["eol"]
                        })
                        logger.info(f"Framework {name} version {version} is past EOL date {eol_date_str}. Suggested upgrade to version {latest_version['cycle']} with EOL date {latest_version['eol']}.")
                    else:
                        logger.info(f"Framework {name} version {version} is within EOL date {eol_date_str}.")
                else:
                    logger.warning(f"No valid EOL date found for framework {name} version {version}.")
            else:
                logger.warning(f"No data found for framework {name} version {version}.")
        else:
            logger.error(f"Failed to fetch EOL data for framework {name}.")
    logger.info(f"Suggested upgrades: {upgrades}")
    return upgrades

async def load_and_check_sbom():
    """Load the SBOM from sbom.json, parse it, and check EOL dates."""
    sbom_path = os.getenv('SBOM_PATH', os.path.join(os.path.dirname(__file__), 'sbom.json'))
    logger.info(f"SBOM path: {sbom_path}")

    try:
        with open(sbom_path, 'r') as file:
            sbom = file.read()
            logger.info("SBOM file loaded successfully.")
    except FileNotFoundError:
        logger.error(f"SBOM file not found: {sbom_path}")
        return None
    except Exception as e:
        logger.error(f"Error reading SBOM file: {e}")
        return None

    config = RunnableConfig()  # Assuming a default config for now
    logger.info("Loading SBOM...")
    try:
        frameworks = await parse_sbom(sbom, config=config)
        if frameworks:
            logger.info(f"Parsed frameworks: {frameworks}")
            upgrades = await check_eol_dates(frameworks, config=config)
            logger.info(f"Frameworks: {frameworks}")
            logger.info(f"Upgrades: {upgrades}")
            return frameworks
        else:
            logger.error("Failed to parse SBOM or no frameworks found.")
            return None
    except Exception as e:
        logger.error(f"Error processing SBOM: {e}")
        return None

TOOLS: List[Callable[..., Any]] = [search, parse_sbom, fetch_eol_data, check_eol_dates, load_and_check_sbom]