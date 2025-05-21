#!/usr/bin/env python3
import sys
import json
import re
import os
import logging
import warnings
import urllib.request
import urllib.error
import urllib.parse
import ssl
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Disable SSL warnings for internal corporate environments
# This is often necessary for corporate environments with self-signed certificates
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Function to convert HTML to plain text with better formatting preservation
def html_to_text(html_content):
    # Process the content in stages to better preserve structure
    
    # 1. Handle special Confluence macros and elements
    html_content = re.sub(r'<ac:link[^>]*>.*?</ac:link>', '', html_content)  # Remove Confluence links
    
    # 2. Handle headers
    html_content = re.sub(r'<h1[^>]*>(.*?)</h1>', r'\n\n# \1\n\n', html_content)
    html_content = re.sub(r'<h2[^>]*>(.*?)</h2>', r'\n\n## \1\n\n', html_content)
    html_content = re.sub(r'<h3[^>]*>(.*?)</h3>', r'\n\n### \1\n\n', html_content)
    html_content = re.sub(r'<h4[^>]*>(.*?)</h4>', r'\n\n#### \1\n\n', html_content)
    html_content = re.sub(r'<h5[^>]*>(.*?)</h5>', r'\n\n##### \1\n\n', html_content)
    html_content = re.sub(r'<h6[^>]*>(.*?)</h6>', r'\n\n###### \1\n\n', html_content)
    
    # 3. Handle lists - preserve nesting structure
    # Convert unordered lists
    html_content = re.sub(r'<ul[^>]*>', r'\n', html_content)
    html_content = re.sub(r'</ul>', r'\n', html_content)
    
    # Convert list items with proper indentation
    html_content = re.sub(r'<li[^>]*>(.*?)</li>', r'- \1\n', html_content)
    
    # Convert ordered lists
    html_content = re.sub(r'<ol[^>]*>', r'\n', html_content)
    html_content = re.sub(r'</ol>', r'\n', html_content)
    
    # 4. Handle paragraphs and line breaks
    html_content = re.sub(r'<p[^>]*>(.*?)</p>', r'\n\n\1\n\n', html_content)
    html_content = re.sub(r'<br[^>]*>', r'\n', html_content)
    html_content = re.sub(r'<div[^>]*>(.*?)</div>', r'\n\1\n', html_content)
    
    # 5. Handle text formatting
    html_content = re.sub(r'<strong[^>]*>(.*?)</strong>', r'**\1**', html_content)
    html_content = re.sub(r'<b[^>]*>(.*?)</b>', r'**\1**', html_content)
    html_content = re.sub(r'<em[^>]*>(.*?)</em>', r'*\1*', html_content)
    html_content = re.sub(r'<i[^>]*>(.*?)</i>', r'*\1*', html_content)
    html_content = re.sub(r'<u[^>]*>(.*?)</u>', r'_\1_', html_content)
    html_content = re.sub(r'<code[^>]*>(.*?)</code>', r'`\1`', html_content)
    html_content = re.sub(r'<pre[^>]*>(.*?)</pre>', r'```\n\1\n```', html_content, flags=re.DOTALL)
    
    # 6. Handle links
    html_content = re.sub(r'<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>', r'[\2](\1)', html_content)
    
    # 7. Handle tables (simplified conversion)
    html_content = re.sub(r'<table[^>]*>.*?</table>', r'\n[Table content omitted]\n', html_content, flags=re.DOTALL)
    
    # 8. Remove remaining HTML tags
    html_content = re.sub(r'<[^>]+>', ' ', html_content)
    
    # 9. Replace HTML entities
    entities = {
        '&nbsp;': ' ',
        '&lt;': '<',
        '&gt;': '>',
        '&amp;': '&',
        '&quot;': '"',
        '&apos;': "'",
        '&ldquo;': '"',
        '&rdquo;': '"',
        '&lsquo;': "'",
        '&rsquo;': "'",
        '&mdash;': '—',
        '&ndash;': '–',
        '&rarr;': '→',
        '&larr;': '←',
        '&uarr;': '↑',
        '&darr;': '↓',
        '&hellip;': '...',
    }
    
    for entity, replacement in entities.items():
        html_content = html_content.replace(entity, replacement)
    
    # 10. Clean up excessive whitespace while preserving paragraph breaks
    # Replace multiple newlines with just two (to create paragraph breaks)
    html_content = re.sub(r'\n{3,}', '\n\n', html_content)
    
    # Replace multiple spaces with a single space
    html_content = re.sub(r' +', ' ', html_content)
    
    # Trim leading/trailing whitespace
    html_content = html_content.strip()
    
    return html_content

def get_confluence_url() -> str:
    """Get the Confluence server URL from environment"""
    server_url = os.getenv("CONFLUENCE_URL")
    if not server_url:
        raise ValueError("CONFLUENCE_URL environment variable must be set")
    url = server_url.rstrip('/')  # Remove trailing slash if present
    logger.info(f"Using Confluence server URL: {url}")
    return url

def get_confluence_auth() -> tuple:
    """Get Confluence username and password from environment"""
    creds = os.getenv("CONFLUENCE_USER_CREDS")
    if not creds:
        raise ValueError("CONFLUENCE_USER_CREDS environment variable must be set (format: username:password)")
    try:
        username, password = creds.split(":", 1)  # Use 1 to handle passwords with colons
        return (username, password)
    except ValueError:
        raise ValueError("CONFLUENCE_USER_CREDS must be in format 'username:password'")

def get_confluence_basic_headers() -> dict:
    """Get basic headers for Confluence API requests"""
    return {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

def setup_client_cert_files():
    """
    Gets client certificate and key from environment variables and writes them to files.
    Returns tuple of (cert_path, key_path).
    """
    logger.info("Setting up client certificate files...")
    
    # Get certificate and key content from environment variables
    CLIENT_CERT = os.getenv("CONFLUENCE_CLIENT_CERT")
    CLIENT_KEY = os.getenv("CONFLUENCE_CLIENT_KEY")

    if not CLIENT_CERT or not CLIENT_KEY:
        raise ValueError("CONFLUENCE_CLIENT_CERT and CONFLUENCE_CLIENT_KEY environment variables must be set")

    # Log certificate details (safely)
    logger.info("Certificate validation:")
    logger.info(f"Certificate length: {len(CLIENT_CERT)} characters")
    logger.info(f"Private key length: {len(CLIENT_KEY)} characters")
    logger.info(f"Certificate starts with: {CLIENT_CERT[:25]}...")
    logger.info(f"Private key starts with: {CLIENT_KEY[:25]}...")

    # Create temporary paths for the cert files
    cert_path = "/tmp/confluence_client.crt"
    key_path = "/tmp/confluence_client.key"

    # Write the certificates to files
    try:
        # Ensure the certificate content is properly formatted
        if "BEGIN CERTIFICATE" not in CLIENT_CERT:
            logger.info("Adding certificate markers")
            CLIENT_CERT = f"-----BEGIN CERTIFICATE-----\n{CLIENT_CERT}\n-----END CERTIFICATE-----"
        if "BEGIN PRIVATE KEY" not in CLIENT_KEY:
            logger.info("Adding private key markers")
            CLIENT_KEY = f"-----BEGIN PRIVATE KEY-----\n{CLIENT_KEY}\n-----END PRIVATE KEY-----"

        logger.info(f"Writing certificate to: {cert_path}")
        with open(cert_path, 'w') as f:
            f.write(CLIENT_CERT)
        
        logger.info(f"Writing private key to: {key_path}")
        with open(key_path, 'w') as f:
            f.write(CLIENT_KEY)

        # Set proper permissions
        os.chmod(cert_path, 0o644)
        os.chmod(key_path, 0o600)

        # Verify files exist and have content
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            raise ValueError("Certificate files were not created properly")
        
        cert_size = os.path.getsize(cert_path)
        key_size = os.path.getsize(key_path)
        logger.info(f"Certificate file size: {cert_size} bytes")
        logger.info(f"Private key file size: {key_size} bytes")
        
        if cert_size == 0 or key_size == 0:
            raise ValueError("Certificate files are empty")

        # Read back files to verify content
        with open(cert_path, 'r') as f:
            cert_content = f.read()
            logger.info(f"Certificate file contains BEGIN/END markers: {('BEGIN CERTIFICATE' in cert_content)} / {('END CERTIFICATE' in cert_content)}")
        
        with open(key_path, 'r') as f:
            key_content = f.read()
            logger.info(f"Key file contains BEGIN/END markers: {('BEGIN PRIVATE KEY' in key_content)} / {('END PRIVATE KEY' in key_content)}")

        return cert_path, key_path

    except Exception as e:
        logger.error(f"Error setting up certificate files: {str(e)}")
        raise

def test_confluence_connection():
    """Test the Confluence connection with current credentials"""
    try:
        logger.info("\n=== Testing Confluence Connection ===")
        server_url = get_confluence_url()
        
        # Try to access a simple endpoint
        test_url = f"{server_url}/rest/api/space?limit=1"
        logger.info(f"Testing connection to: {test_url}")
        
        # Make the test request
        test_result = make_request(test_url)
        
        if "error" in test_result:
            logger.error(f"Connection test failed: {test_result['error']}")
            return False
        else:
            logger.info("Successfully connected to Confluence!")
            return True
            
    except Exception as e:
        logger.error(f"Connection test failed with exception: {str(e)}")
        return False

def make_request(url):
    """
    Make a request to Confluence API using certificate auth but with urllib like the original
    """
    try:
        # Get auth credentials
        auth = get_confluence_auth()
        if not auth:
            return {"error": "No authentication credentials provided"}
        
        username, password = auth
        
        # Create authorization header
        auth_str = f"{username}:{password}"
        auth_bytes = auth_str.encode('ascii')
        base64_bytes = base64.b64encode(auth_bytes)
        auth_header = f"Basic {base64_bytes.decode('ascii')}"
        
        # Create request with headers
        req = urllib.request.Request(url)
        req.add_header('Authorization', auth_header)
        req.add_header('Accept', 'application/json')
        
        # Get client certificates
        try:
            cert_path, key_path = setup_client_cert_files()
            
            # Create SSL context with client certificates
            context = ssl.create_default_context()
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Disable SSL verification
            
            # Make request with SSL context
            logger.info(f"Making request to: {url} with certificate auth")
            response = urllib.request.urlopen(req, context=context, timeout=30)
            
        except Exception as e:
            logger.warning(f"Certificate auth failed: {str(e)}")
            logger.warning("Falling back to basic auth without certificates")
            
            # Create SSL context without client certificates
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Disable SSL verification
            
            # Make request with SSL context
            logger.info(f"Making request to: {url} with basic auth")
            response = urllib.request.urlopen(req, context=context, timeout=30)
        
        # Read and decode response
        data = response.read().decode('utf-8')
        return json.loads(data)
        
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP Error: {e.code} - {e.reason}")
        return {"error": f"HTTP Error: {e.code} - {e.reason}"}
    except urllib.error.URLError as e:
        logger.error(f"URL Error: {e.reason}")
        return {"error": f"URL Error: {e.reason}"}
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return {"error": f"Error: {str(e)}"}

def main():
    # Read input from stdin
    try:
        input_data = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        print(json.dumps({"error": "Failed to parse input JSON"}))
        sys.exit(1)
    
    # Extract parameters
    space_key = input_data.get("space_key", "")
    include_blogs = input_data.get("include_blogs", "true").lower() == "true"
    
    # Set environment variables from input data if provided
    if "CONFLUENCE_URL" in input_data:
        os.environ["CONFLUENCE_URL"] = input_data["CONFLUENCE_URL"]
    if "CONFLUENCE_USER_CREDS" in input_data:
        os.environ["CONFLUENCE_USER_CREDS"] = input_data["CONFLUENCE_USER_CREDS"]
    if "CONFLUENCE_CLIENT_CERT" in input_data:
        os.environ["CONFLUENCE_CLIENT_CERT"] = input_data["CONFLUENCE_CLIENT_CERT"]
    if "CONFLUENCE_CLIENT_KEY" in input_data:
        os.environ["CONFLUENCE_CLIENT_KEY"] = input_data["CONFLUENCE_CLIENT_KEY"]
    
    # Check for required parameters
    if not space_key:
        print(json.dumps({"error": "Missing required parameter: space_key"}))
        sys.exit(1)
    
    try:
        # Get Confluence URL
        confluence_url = get_confluence_url()
        
        # Test connection
        logger.info(f"Testing connection to Confluence at {confluence_url}")
        if not test_confluence_connection():
            print(json.dumps({"error": "Confluence connection failed"}))
            sys.exit(1)
        
        # Get space content
        content_url = f"{confluence_url}/rest/api/space/{space_key}/content?limit=100"
        content_result = make_request(content_url)
        
        if "error" in content_result:
            print(json.dumps({"error": f"Failed to retrieve content: {content_result['error']}"}))
            sys.exit(1)
        
        # Process pages and blogs
        items = []
        
        # Process pages
        if "page" in content_result and "results" in content_result["page"]:
            for page in content_result["page"]["results"]:
                page_id = page.get("id")
                if page_id:
                    # Get page content
                    page_url = f"{confluence_url}/rest/api/content/{page_id}?expand=body.storage,metadata.labels"
                    page_data = make_request(page_url)
                    
                    if "error" not in page_data:
                        # Extract content and labels
                        content = page_data.get("body", {}).get("storage", {}).get("value", "")
                        clean_content = html_to_text(content)
                        
                        # Skip empty pages
                        if not clean_content or clean_content.strip() == "":
                            continue
                        
                        # Extract labels
                        labels = []
                        if "metadata" in page_data and "labels" in page_data["metadata"] and "results" in page_data["metadata"]["labels"]:
                            for label in page_data["metadata"]["labels"]["results"]:
                                if "name" in label:
                                    labels.append(label["name"])
                        
                        # Add to items
                        items.append({
                            "id": page_data.get("id"),
                            "title": page_data.get("title", "Untitled"),
                            "content": clean_content,
                            "type": "page",
                            "labels": ",".join(labels)  # Convert array to comma-separated string
                        })
        
        # Process blogs if requested
        if include_blogs and "blogpost" in content_result and "results" in content_result["blogpost"]:
            for blog in content_result["blogpost"]["results"]:
                blog_id = blog.get("id")
                if blog_id:
                    # Get blog content
                    blog_url = f"{confluence_url}/rest/api/content/{blog_id}?expand=body.storage,metadata.labels"
                    blog_data = make_request(blog_url)
                    
                    if "error" not in blog_data:
                        # Extract content and labels
                        content = blog_data.get("body", {}).get("storage", {}).get("value", "")
                        clean_content = html_to_text(content)
                        
                        # Skip empty blogs
                        if not clean_content or clean_content.strip() == "":
                            continue
                        
                        # Extract labels
                        labels = []
                        if "metadata" in blog_data and "labels" in blog_data["metadata"] and "results" in blog_data["metadata"]["labels"]:
                            for label in blog_data["metadata"]["labels"]["results"]:
                                if "name" in label:
                                    labels.append(label["name"])
                        
                        # Add to items
                        items.append({
                            "id": blog_data.get("id"),
                            "title": blog_data.get("title", "Untitled"),
                            "content": clean_content,
                            "type": "blog",
                            "labels": ",".join(labels)  # Convert array to comma-separated string
                        })
        
        # Convert the items list to a JSON string
        items_json = json.dumps(items)
        
        # Return the items as a string value
        print(json.dumps({"items": items_json}))
        
    except ValueError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {str(e)}"}))
        sys.exit(1)

if __name__ == "__main__":
    main()