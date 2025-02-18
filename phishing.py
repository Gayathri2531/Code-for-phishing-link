import requests
import re
from urllib.parse import urlparse

# Function to check if the URL contains suspicious patterns
def is_url_suspicious(url):
    # List of regex patterns that indicate a potentially malicious URL
    suspicious_patterns = [
        r'http:\/\/',  # Unsecured HTTP (HTTPS is safer)
        r'bit\.ly|tinyurl\.com|goo\.gl',  # Shortened URLs (commonly used to hide phishing links)
        r'free|win|prize|click|verify',  # Common phishing-related words
    ]
    
    # Check if the URL matches any of the suspicious patterns
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):  # Case-insensitive search
            return True  # URL is suspicious
    return False  # URL is not suspicious

# Function to check the URL against Google Safe Browsing API for known threats
def check_google_safebrowsing(api_key, url):
    try:
        # Google Safe Browsing API endpoint
        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

        # API request payload (contains threat types and URL to be checked)
        payload = {
            "client": {"clientId": "yourcompany", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],  # Checks for malware & phishing threats
                "platformTypes": ["ANY_PLATFORM"],  # Checks for threats across all platforms
                "threatEntryTypes": ["URL"],  # URL-based threats
                "threatEntries": [{"url": url}]  # URL to be checked
            }
        }

        # Send POST request to Google Safe Browsing API
        response = requests.post(endpoint, json=payload, params={"key": api_key})
        response.raise_for_status()  # Raise an error if request fails

        # Parse JSON response
        result = response.json()

        # If "matches" key is in response, URL is flagged as unsafe
        return "matches" in result
    except requests.exceptions.RequestException:
        return False  # Return False if there's a request error

# Function to extract and return details from the given URL
def get_url_details(url):
    parsed_url = urlparse(url)  # Parse the URL into components
    return {
        "original_url": url,  # The original URL provided by the user
        "scheme": parsed_url.scheme,  # URL scheme (http, https)
        "domain": parsed_url.netloc,  # Domain name (e.g., example.com)
        "path": parsed_url.path,  # URL path (e.g., /login)
        "query": parsed_url.query,  # Query parameters (e.g., ?user=123)
        "fragment": parsed_url.fragment  # Fragment (e.g., #section1)
    }

# Function to follow redirects and determine the final destination of a URL
def follow_redirects(url):
    try:
        # Send GET request with redirect enabled
        response = requests.get(url, allow_redirects=True, timeout=5)

        # Capture the final destination URL after all redirects
        final_url = response.url

        # Store all redirections in a list
        redirect_chain = [resp.url for resp in response.history] + [final_url]

        return redirect_chain  # Return the list of all redirects
    except requests.exceptions.RequestException:
        return ["Failed to retrieve URL"]  # Return error message if request fails

# Main function to analyze the URL
def analyze_url(url, api_key):
    details = get_url_details(url)  # Extract URL components
    redirects = follow_redirects(url)  # Get redirection chain

    # Store final destination (last URL in the redirect chain)
    details["final_destination"] = redirects[-1] if redirects else "Unknown"

    # Store the entire redirect chain
    details["redirect_chain"] = redirects

    # Check if the URL is suspicious
    details["is_suspicious"] = is_url_suspicious(url)

    # Check if the URL is flagged by Google Safe Browsing
    details["google_safe_browsing"] = check_google_safebrowsing(api_key, url)

    # Determine trust status based on the checks
    if details["is_suspicious"] or details["google_safe_browsing"]:
        details["trust_status"] = "🚨 NOT TRUSTED 🚨"  # Mark as unsafe
    else:
        details["trust_status"] = "✅ TRUSTED ✅"  # Mark as safe

    return details  # Return the final analysis

# Main execution block
if __name__ == "__main__":
    api_key = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"  # Replace with actual API key
    url = input("Enter the URL to check: ")  # Get URL input from user

    # Analyze the given URL
    result = analyze_url(url, api_key)

    # Print analysis results
    print("\n🔍 URL Analysis:")
    for key, value in result.items():
        print(f"{key}: {value}")  # Display each key-value pair

    # Display final trust status
    print(f"\n🔴 Status: {result['trust_status']}")
