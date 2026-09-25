import asyncio
import httpx
import os
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def main():
    token = os.environ["AGENTTRUST_JWT"]
    url = "http://127.0.0.1:8000/mcp"

    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"}
    ) as http_client:
        async with streamable_http_client(
            url,
            http_client=http_client,
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools = await session.list_tools()
                print([tool.name for tool in tools.tools])

                result = await session.call_tool(
                    "ticket.get",
                    {"ticket_id": "481"},
                )
                print(result)


asyncio.run(main())
