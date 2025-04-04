# Paramy

Paramy it grabs paramters in a website.

## Features


## Installation

```bash
# Using Go Install
go install github.com/yourusername/paramy@latest

# Or build from source
git clone https://github.com/yourusername/paramy.git
cd paramy
go build
```

## Quick Start

```bash
# Scan a single domain
./paramy -d example.com

# Scan multiple domains from a file
./paramy -l domains.txt

# Enable parameter reflection checking
./paramy -d example.com -r

# Use with brute force (requires wordlist)
./paramy -d example.com -b -w params.txt

# Use with proxy
./paramy -d example.com -proxy http://127.0.0.1:8080
```

## How It Works

1. **URL Collection**: Paramy gathers URLs from multiple sources:
   - Wayback Machine (Internet Archive)
   - Common Crawl
   - AlienVault OTX
   - URLScan.io

2. **Parameter Extraction**: For each URL, Paramy extracts existing query parameters and replaces values with a placeholder.

3. **Parameter Testing** (when reflection testing is enabled):
   - Paramy injects a unique value into each parameter
   - It then checks if the value is reflected in the response
   - Parameters that reflect input are marked as potential XSS vectors

4. **Brute Force** (when enabled):
   - Tests common paths with parameters from a wordlist
   - Helps discover hidden or undocumented parameters

5. **Results Processing**:
   - Saves a JSON file with detailed information about each parameter
   - Creates a plain text file with URLs for use with other tools

## Command Line Options

```
  -d string       Domain to scan for parameters
  -l string       File containing list of domains
  -o string       Output directory for results (default "results")
  -p string       Placeholder for parameter values (default "FUZZ")
  -t int          Number of concurrent threads (default 10)
  -timeout int    HTTP request timeout in seconds (default 30)
  -proxy string   Proxy URL (e.g., http://127.0.0.1:8080)
  -v              Verbose output
  -s              Stream results to terminal
  -w string       Parameter wordlist for brute forcing
  -b              Enable parameter brute forcing
  -depth int      Brute force crawl depth (default 1)
  -r              Check for parameter reflection
```

## Output Files

For each domain, Paramy generates:

1. **{domain}.json**: Detailed JSON file containing:
   - URLs with parameter placeholders
   - Parameter names
   - Reflective parameters (if tested)
   - Source information

2. **{domain}.txt**: Plain text file with URLs for use with other tools

## Example Output

```json
[
  {
    "url": "https://example.com/search?q=FUZZ&page=FUZZ",
    "parameters": ["q", "page"],
    "reflective": ["q"],
    "source": "archive"
  },
  {
    "url": "https://example.com/api?id=FUZZ&token=FUZZ",
    "parameters": ["id", "token"],
    "source": "archive"
  }
]
```

## Tips for Effective Use

- **Use Multiple Sources**: Try all sources for maximum coverage
- **Enable Reflection Testing**: Helps identify potential XSS vectors
- **Combine with Wordlists**: Use high-quality parameter wordlists for brute forcing
- **Pair with Proxy**: Route traffic through Burp Suite or ZAP for deeper analysis
- **Filter Results**: Process the output files to focus on interesting parameters

## Use Cases

- Discovering hidden API parameters
- Finding potential XSS vectors through parameter reflection
- Mapping application attack surface
- Identifying legacy parameters that might be poorly protected
- Discovering parameters across subdomains and related applications
