"""Reads an NDJSON file from provided input file, extracts CVE IDs, and queries NVD for enrichments"""
import argparse
import json
import logging
import os
from functools import lru_cache
from sys import stderr, stdin, stdout
from time import sleep

import httpx
import tqdm
from dotenv import load_dotenv
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("cvss_enrich")

client: httpx.AsyncClient = httpx.AsyncClient()

NVD_API_KEY = ""


@lru_cache(maxsize=None)
async def lookup_cve(cve_id: str):
    """Sends a request to NVD to get CVSS data for the given CVE ID"""
    _logger = logger.getChild("lookup_cve")
    try:
        if NVD_API_KEY:
            response = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                headers={"apiKey": NVD_API_KEY},
            )
        else:
            response = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            )
        if response.status_code == 200:
            return response.json()
        else:
            _logger.error(
                f"Unexpected response from NVD: {response.status_code}\t{response.text}"
            )
    except Exception as e:
        _logger.error(f"Error fetching CVE {cve_id}: {e}")
        _logger.error(response.text)
        return None


class CVEReturn(BaseModel):
    cvss3_score: float = 0.0
    cvss3_vector: str = ""
    cvss3_exploitability: float = 0.0
    cvss3_base_severity: str = ""
    cvss2_score: float = 0.0
    cvss2_vector: str = ""
    cvss2_exploitability: float = 0.0
    cvss2_base_severity: str = ""


def parse_response(response: dict) -> CVEReturn:
    """Parses a response from NVD and returns a CVEReturn object"""
    _logger = logger.getChild("parse_response")
    try:
        if vulnerabilities := response.get("vulnerabilities"):
            if metrics := vulnerabilities[0].get("cve").get("metrics"):
                ret = {
                    "cvss3_vector": "",
                    "cvss3_score": 0.0,
                    "cvss3_exploitability": 0.0,
                    "cvss3_base_severity": "UNKNOWN",
                    "cvss2_vector": "",
                    "cvss2_score": 0.0,
                    "cvss2_exploitability": 0.0,
                    "cvss2_base_severity": "UNKNOWN",
                }
                if "cvssMetricV31" in metrics.keys():
                    m = metrics["cvssMetricV31"][0]
                    ret["cvss3_vector"] = m.get("cvssData").get(
                        "vectorString", ret["cvss3_vector"]
                    )
                    ret["cvss3_score"] = m.get("cvssData").get(
                        "baseScore", ret["cvss3_score"]
                    )
                    ret["cvss3_exploitability"] = m.get(
                        "exploitability", ret["cvss3_exploitability"]
                    )
                    ret["cvss3_base_severity"] = m.get("cvssData").get(
                        "baseSeverity", ret["cvss3_base_severity"]
                    )
                if "cvssMetricV2" in metrics.keys():
                    m = metrics["cvssMetricV2"][0]
                    ret["cvss2_vector"] = m.get("cvssData").get(
                        "vectorString", ret["cvss2_vector"]
                    )
                    ret["cvss2_score"] = m.get("cvssData").get(
                        "baseScore", ret["cvss2_score"]
                    )
                    ret["cvss2_exploitability"] = m.get(
                        "exploitability", ret["cvss2_exploitability"]
                    )
                    ret["cvss2_base_severity"] = m.get(
                        "baseSeverity", ret["cvss2_base_severity"]
                    )
                return CVEReturn(**ret)
        else:
            _logger.error(f"Unexpected response from NVD: {response}")
    except Exception as e:
        _logger.error(f"Error parsing response: {e}")
        _logger.error(response)
        return None


def parse_args():
    parser = argparse.ArgumentParser(
        description="Queries NVD for CVSS data, enriching NDJSON input"
    )
    parser.add_argument(
        "-i",
        "--input-file",
        type=argparse.FileType("r"),
        default=stdin,
        help="File to read input from",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        type=argparse.FileType("w"),
        default=stdout,
        help="File to write output to",
    )
    parser.add_argument(
        "--cve-key",
        default="cve",
        help="Key to use to extract CVE ID from input",
        type=str,
    )
    logger_group = parser.add_argument_group("Logging")
    logger_group.add_argument(
        "--debug", action="store_true", help="Enable debug logging.", default=False
    )
    quiet_group = logger_group.add_mutually_exclusive_group(required=False)
    quiet_group.add_argument(
        "--quiet",
        action="store_true",
        dest="quiet",
        help="Set logging level to WARNING.",
    )
    quiet_group.add_argument(
        "--no-quiet",
        action="store_false",
        dest="quiet",
        help="Set logging level to INFO.",
    )
    parser.set_defaults(quiet=False)
    parser.add_argument(
        "--no-api-key",
        action="store_true",
        help="Do not use NVD API key - 10x slower.",
    )
    parser.add_argument(
        "--seconds-per-request",
        type=float,
        default=0.75,
        help="Seconds to sleep between each request. Enforces NVD rate limit. Defaults to 0.75 with API key, 7 without.",
    )
    progress_group = parser.add_mutually_exclusive_group(required=False)
    progress_group.add_argument(
        "--no-progress",
        action="store_false",
        help="Remove progress bar.",
        default=False,
        dest="progress",
    )
    progress_group.add_argument(
        "--progress",
        action="store_true",
        help="Add progress bar to stderr. Recommend to send output to a file, otherwise the progress bar will be reprinted with each update.",
        default=False,
        dest="progress",
    )
    parser.set_defaults(progress=False)
    args = parser.parse_args()
    return args


async def main():
    args = parse_args()
    # Look for API key
    if not args.no_api_key:
        load_dotenv()
        global NVD_API_KEY
        NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    if args.no_api_key or not NVD_API_KEY:
        args.seconds_per_request = 7
    if args.quiet:
        logger.setLevel(logging.WARNING)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    input_data = [json.loads(line) for line in args.input_file]
    for index, data in enumerate(
        tqdm.tqdm(
            input_data, desc="Processing CVEs", disable=not args.progress, file=stderr
        )
    ):
        try:
            if args.cve_key in data.keys():
                # we gain nothing with async here, but useful if nvd updates their rate limiting
                resp = await lookup_cve(data[args.cve_key])
                cve_info = parse_response(resp)
                if cve_info:
                    data.update(cve_info.model_dump())
                    args.output_file.write(f"{json.dumps(data, indent=None)}\n")
                else:
                    logger.warning(f"No return for {data[args.cve_key]}")
            else:
                logger.warning(f"Skipping improperly-formatted input {data=}")
        except Exception as e:
            logger.error(f"Error processing {data=}: {e}")
            logger.error(resp.text)
            continue
        # This should block
        if index < len(input_data) - 1:
            sleep(args.seconds_per_request)


def run():
    import asyncio

    asyncio.run(main())


if __name__ == "__main__":
    run()
