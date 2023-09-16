import requests
import re

def is_potential_sqli(url):
    sqli_keywords = [
        r'\bselect\b',      # Matches 'select' keyword (e.g., parameter=select ...)
        r'\bunion\b',       # Matches 'union' keyword (e.g., parameter=value union select ...)
        r'\bfrom\b',        # Matches 'from' keyword (e.g., parameter=value from table)
        r'\bwhere\b',       # Matches 'where' keyword (e.g., parameter=value where 1=1)
        r'\binsert\b',      # Matches 'insert' keyword (e.g., parameter=insert ...)
        r'\bupdate\b',      # Matches 'update' keyword (e.g., parameter=update ...)
        r'\bdelete\b',      # Matches 'delete' keyword (e.g., parameter=delete ...)
    ]

    # Extract parameters from the URL
    query_params = re.findall(r'\?(.*)', url)
    if not query_params:
        return False

    # Check each parameter for potential SQL injection keywords
    for param in query_params:
        for keyword in sqli_keywords:
            if re.search(keyword, param, re.IGNORECASE):
                return True

    return False

# Read URLs from the file and store them in a list
def read_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.read().splitlines()
    return urls

# Provide the file path where the URLs are stored
file_path = 'urls.txt'

# Read URLs from the file
urls = read_urls_from_file(file_path)

# Test each URL for potential SQL injection vulnerabilities
for url in urls:
    if is_potential_sqli(url):
        print(f"Potential SQL Injection Vulnerability Detected in URL: {url}")
    else:
        print(f"No SQL Injection Vulnerability Found in URL: {url}")
