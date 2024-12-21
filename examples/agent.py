"""
Example AI Agent that uses the Nillion toolkit.
"""
import os
import sys
import asyncio

# Use local source directory - move this BEFORE imports
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.prompts import PromptTemplate
from nillion_toolkit import NillionToolkit
from nillion_toolkit import toolkit

# Initialize
load_dotenv()
llm = ChatOpenAI(temperature=0)

# Get tools
toolkit = NillionToolkit()
tools = toolkit.get_tools()
tool_names = [tool.name for tool in tools]
tool_descriptions = [f"{tool.name}: {tool.description}" for tool in tools]

# Create prompt template
TEMPLATE = """Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action. if something has been initiated, wait for it to complete.
Thought: I've seen the result of the action and the payload if there is one. I now know the final answer and if there are any errors.
Final Answer: summarize the result of the action. if there was a payload returned by the tool, show the full payload after answering. If there is a transaction initiated, show the transaction hash after answering.

Question: {input}
{agent_scratchpad}"""

prompt = PromptTemplate(
    template=TEMPLATE,
    input_variables=["input", "agent_scratchpad"],
    partial_variables={
        "tools": "\n".join(tool_descriptions),
        "tool_names": ", ".join(tool_names)
    }
)

# Create agent
agent = create_openai_functions_agent(llm, tools, prompt)
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True
)

async def run_default_sequence():
    """Run the default sequence of tool calls."""
    print("--- Get the user ID from the seed ---")
    user_id_tool = tools[0]
    user_id = await user_id_tool.arun(tool_input={
        "user_key_seed": "test"
    })
    print(f"User ID: {user_id}")

    print("--- Sign a simple message ---")
    sign_tool = tools[1]
    signature = await sign_tool.arun(tool_input={
        "message_type": "simple",
        "message": "Hello, Nillion!",
    })
    print(f"Simple message signature: {signature}")

    print("--- Send a transaction ---")
    send_tx_tool = tools[2]
    tx_receipt = await send_tx_tool.arun(tool_input={
        "amount_in_eth": 0.0001,
        "to_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "data": "let's go!"
    })
    print(f"Transaction receipt: {tx_receipt}")

async def main():
    if len(sys.argv) > 1:
        # Get the prompt (combine all arguments to handle multi-word prompts)
        query = " ".join(sys.argv[1:])
        print(f"\nProcessing prompt: {query}\n")
        
        # Run the agent with the prompt and enable verbose output
        response = await agent_executor.ainvoke(
            {"input": query},
            config={"verbose": True}  # This will show us the full chain of thought
        )
        
        # Print the raw tool outputs from the response
        if "intermediate_steps" in response:
            print("\nTool Outputs:")
            for step in response["intermediate_steps"]:
                print(f"\nTool: {step[0]}")
                print(f"Output: {step[1]}")
                
        print("\nFinal Response:", response["output"])
    else:
        # Run default sequence if no prompt provided
        print("\nNo prompt provided. Running default sequence...\n")
        await run_default_sequence()

if __name__ == "__main__":
    asyncio.run(main())