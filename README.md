# bbot-utils

Tools for parsing/enriching data from bbot. Designed to be generally useful, since it can parse arbitrary NDJSON files.

## Installation

Recommended installation method is with pipx, since this also adds the tools to your path.

```sh
pipx install git+https://github.com/cnnrshd/bbot-utils.git
```

This allows you to simply run:

```sh
echo '{"host":"1.1.1.1"}' | ip_enrich -o out.json
echo '{"cve":"CVE-2022-0001"}' | cvss_enrich -o out.json
```

### Requirements - API keys

cvss_enrich and ip_enrich both support querying without an API key. For `cvss_enrich`, which uses NVD, the query rate is 10x slower. For `ip_enrich`, which uses Shodan, you may get rate-limited since this is potentially not-allowed. Not an isuse if you use the default `--internetdb` search.

### Requirements - Python Packages

Handled if you use pipx, here is the dump from pyproject (minor version differences should work, but are untested):

python-dotenv = "^1.0.0"
httpx = "^0.25.0"
aiometer = "^0.5.0"
tqdm = "^4.66.1"
pydantic = "^2.5.2"

## cvss_enrich.py

`cvss_enrich.py` is a Python script that reads a newline-delimited JSON (ndjson) file, extracts CVE IDs, and queries NVD for CVE enrichments. In particular, this extracts cvss v2 and v3 score, exploitability, vector string, and severity.

### Usage

Subject to change. Check the `--help` flag.

```bash
python cvss_enrich.py [-h] [-i INPUT_FILE] [-o OUTPUT_FILE] [--cve-key CVE_KEY] [--debug] [--quiet | --no-quiet] [--no-api-key] [--seconds-per-request SECONDS_PER_REQUEST] [--no-progress | --progress]
```

#### Arguments

- `-h, --help`: Show this help message and exit.
- `-i INPUT_FILE, --input-file INPUT_FILE`: File to read input from.
- `-o OUTPUT_FILE, --output-file OUTPUT_FILE`: File to write output to.
- `--cve-key CVE_KEY`: Key to use to extract CVE ID from input.
- `--debug`: Enable debug logging.
- `--quiet`: Set logging level to WARNING.
- `--no-quiet`: Set logging level to INFO.
- `--no-api-key`: Do not use NVD API key - 10x slower.
- `--seconds-per-request SECONDS_PER_REQUEST`: Seconds to sleep between each request. Enforces NVD rate limit. Defaults to 0.75 with API key, 7 without.
- `--no-progress`: Remove progress bar.
- `--progress`: Add progress bar to stderr. Recommend to send output to a file, otherwise the progress bar will be reprinted with each update.

### Example

```sh
echo '{"cve":"CVE-2017-9798"}' | python ./bbot-utils/cvss_enrich.py | jq
```

Expected output:

```json
{
  "cve": "CVE-2017-9798",
  "cvss3_score": 7.5,
  "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "cvss3_exploitability": 0,
  "cvss3_base_severity": "HIGH",
  "cvss2_score": 5,
  "cvss2_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
  "cvss2_exploitability": 0,
  "cvss2_base_severity": "MEDIUM"
}
```

## ip_enrich.py

`ip_enrich.py` is a Python script that reads a newline-delimited JSON (ndjson) file, extracts IP addresses, and queries Shodan for additional information about the IP addresses. The enriched results are then written to an output file.

### Usage

Subject to change. Check the `--help` flag.

You can run the script from the command line with the following syntax:

```bash
python ip_enrich.py [-i INPUT] [-o OUTPUT] [-k IP_KEY] [--enrichment-keys [ENRICHMENT_KEYS ...]] [--minify | --no-minify] [--debug] [--quiet | --no-quiet] [--progress | --no-progress] [--rate RATE] [--no-api-key]
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

## Pipelining

These tools are designed to be pipelined. Starting with just a base IP address, we can find all CVEs and enrich them with NVD, then extract any results that have a CVSS V2 or V3 score greater than 7:

```sh
echo '{"host": "213.183.57.164"}' \
| poetry run ip_enrich --enrichment-keys hostnames vulns  \
| jq -c '{cve : .vulns[1:10][]} + (. | del(.vulns))' \
| poetry run cvss_enrich --progress --quiet \
| jq -c 'select((.cvss3_score >= 7) or (.cvss2_score >= 7))' > out.json
```
