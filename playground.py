import asyncio

async def fetch_data():
    print("Fetching data...")
    await asyncio.sleep(2)  # Simulate a network request
    print("Data fetched")
    return "data"

async def process_data():
    print("Processing data...")
    data = await fetch_data()  # Await the fetch_data coroutine
    print(f"Processed {data}")

async def main():
    await process_data()  # Await the process_data coroutine

# Run the event loop
asyncio.run(main())