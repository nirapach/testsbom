import asyncio
import logging
from react_agent.tools import load_and_check_sbom, check_eol_dates
from react_agent.state import State
from langchain_core.runnables import RunnableConfig
from langchain_core.messages import AIMessage
from react_agent.graph import call_model  # Import the call_model function

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    """Main entry point for the react-agent-1 project."""
    logger.info("Starting the react-agent-1 project...")

    # Create an initial state with a default system message
    initial_state = State(messages=[
        AIMessage(role="system", content="This is the initial system message.")
    ])
    config = RunnableConfig()

    # Call the model with the initial state and configuration
    result = await call_model(initial_state, config)
    logger.info(f"Model result: {result}")

    # Load and check SBOM
    frameworks = await load_and_check_sbom()
    if not frameworks:
        logger.error("Failed to load and check SBOM.")
        return

    # Check EOL dates
    upgrades = await check_eol_dates(frameworks, config=config)
    if upgrades:
        logger.info(f"Suggested upgrades: {upgrades}")
    else:
        logger.error("No upgrades found or failed to process frameworks.")

    # Perform additional steps
    await execute_additional_steps(initial_state, config)

async def execute_additional_steps(state: State, config: RunnableConfig):
    """Execute additional steps after the initial state message."""
    # Example step: Add a user message and call the model again
    state.messages.append(AIMessage(role="user", content="What is the summary of my SBOM and the upgrade recommendations?"))
    result = await call_model(state, config)
    logger.info(f"Model result after user message: {result}")

    # Example step: Add another user message and call the model again
    state.messages.append(AIMessage(role="user", content="Tell me a joke."))
    result = await call_model(state, config)
    logger.info(f"Model result after second user message: {result}")

if __name__ == "__main__":
    asyncio.run(main())