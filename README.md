# bbot-utils

Tools for parsing/enriching data from bbot. Designed to be generally useful, since it can parse arbitrary NDJSON files.

## ip_enrich.py

`ip_enrich.py` is a Python script that reads a newline-delimited JSON (ndjson) file, extracts IP addresses, and queries Shodan for additional information about the IP addresses. The enriched results are then written to an output file.

### Prerequisites

- Python 3.7 or higher
- The following Python packages: `python-dotenv`, `httpx`
- A Shodan API key. This should be set as an environment variable named `SHODAN_API_KEY`.

### Usage

You can run the script from the command line with the following syntax:

```bash
python ip_enrich.py [-i INPUT] [-o OUTPUT] [-k IP_KEY] [--enrichment-keys [ENRICHMENT_KEYS ...]] [--minify | --no-minify] [--debug]
```

#### Arguments

- `-i`, `--input`: The ndjson file to read results from. If not specified, the script will read from stdin.
- `-o`, `--output`: The file to write enriched results to. If not specified, the script will write to stdout.
- `-k`, `--ip_key`: The key to use for IP address extraction. Defaults to 'host'.
- `--enrichment-keys`: The Shodan keys to include in the enriched output. Use 'all' to include all keys. Defaults to 'hostnames' and 'ports'.
- `--minify`: Minify Shodan results. This is the default behavior.
- `--no-minify`: Do not minify Shodan results. Useful if you want full enrichments.
- `--debug`: Enable debug logging. Defaults to false.

### Example

### Example



Here's an example of how to use the script if you just clone the repo:

```bash
echo '{"host":"1.1.1.1"}' | python ./bbot-utils/ip_enrich.py | jq
```

Expected Output:

```json
{
  "host": "1.1.1.1",
  "hostnames": [
    "one.one.one.one"
  ],
  "ports": [
    161,
    2082,
    2083,
    2052,
    69,
    2086,
    2087,
    2095,
    80,
    8880,
    8080,
    53,
    8443,
    443,
    2096,
    2053
  ]
}
```
