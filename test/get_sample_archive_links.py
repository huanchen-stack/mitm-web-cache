import csv
import requests
import json

def read_top_websites(csv_file, num_websites=100):
    """Reads the top websites from a CSV file."""
    top_websites = []
    with open(csv_file, 'r', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if len(top_websites) < num_websites:
                top_websites.append(row[1])  # Assuming the domain is in the second column
            else:
                break
    return top_websites

def get_first_archive_in_2024(website):
    """Fetches the first archive link from 2024 for a given website."""
    api_url = f"http://archive.org/wayback/available?url={website}&timestamp=20240101"
    response = requests.get(api_url)
    if response.status_code == 200:
        data = response.json()
        snapshots = data.get("archived_snapshots")
        if snapshots and "closest" in snapshots:
            return snapshots["closest"]["url"]
    return None

def save_results(archived_links, output_file):
    """Saves the archived links to a JSON file."""
    with open(output_file, 'w', encoding='utf-8') as outfile:
        json.dump(archived_links, outfile, indent=4)

def process_websites(csv_file, output_file):
    """Processes the top websites and saves their first archived link from 2024."""
    print("Reading top websites...")
    top_websites = read_top_websites(csv_file)
    archived_links = {}

    print("Querying Wayback Machine for archives...")
    for website in top_websites:
        archive_link = get_first_archive_in_2024(website)
        if archive_link:
            archived_links[website] = archive_link
            print(f"Found archive for {website}: {archive_link}")
        else:
            print(f"No archive found for {website} in 2024.")

    print("Saving results to file...")
    save_results(archived_links, output_file)
    print(f"Process completed. Results saved to {output_file}.")

# Example usage
csv_file = "samplehosts.csv"  # Replace with your actual file path
output_file = "archived_links_2024.json"
process_websites(csv_file, output_file)
