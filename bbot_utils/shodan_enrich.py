"""Reads a ndjson file from provided input file, extracts the IP address, and queries Shodan for enrichments"""
import argparse
import asyncio
import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from sys import stderr, stdin, stdout
from typing import Callable

import aiometer
from dotenv import load_dotenv
from httpx import AsyncClient
from tqdm import asyncio as tqdm_asyncio

SHODAN_API_KEY = ""
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("ip_enrich")
client = AsyncClient()


@lru_cache(maxsize=None)
async def fetch_ip(ip: str, minify: bool):
    """Queries Shodan's API for the given IP address"""
    _logger = logger.getChild("fetch_ip")
    _logger.info(f"Fetching IP {ip}")
    # Handle no API key
    try:
        if SHODAN_API_KEY == "":
            _logger.warning("No Shodan API key provided.")
            response = await client.get(f"https://api.shodan.io/shodan/host/{ip}")
        else:
            response = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={
                    "key": SHODAN_API_KEY,
                    "minify": minify,
                },
            )
        return response.json()
    except Exception as e:
        _logger.error(f"Error fetching IP {ip}: {e}")
        _logger.error(response.text)
        return None


@lru_cache(maxsize=None)
async def fetch_ip_internetdb(ip: str, *args, **kwargs):
    """Queries Shodan's InternetDB API for the given IP address"""
    _logger = logger.getChild("fetch_ip_internetdb")
    _logger.info(f"Fetching IP {ip}")
    # Handle no API key
    try:
        response = await client.get(f"https://internetdb.shodan.io/{ip}")
        return response.json()
    except Exception as e:
        _logger.error(f"Error fetching IP {ip}: {e}")
        _logger.error(response.text)
        return None


async def enrich(
    data: dict,
    ip_key: str,
    enrichment_keys: list[str],
    minify: bool,
    enrichment_function: Callable,
):
    """Enriches data with Shodan data"""
    _logger = logger.getChild("enrich")
    ip = data[ip_key]
    try:
        shodan_data = await enrichment_function(ip.strip(), minify=minify)
        if shodan_data:
            if enrichment_keys == ["all"]:
                enrichment_keys = shodan_data.keys()
            for key in enrichment_keys:
                if key in shodan_data:
                    data[key] = shodan_data[key]
            return data
        _logger.warning(f"No result returned for IP {ip}")
        return None
    except Exception as e:
        _logger.error(f"Error processing line {shodan_data[ip_key]}: {e}")


@dataclass
class EnrichInput:
    data: dict
    ip_key: str
    enrichment_keys: list[str]
    minify: bool
    enrichment_function: Callable


async def enrich_wrapper(enrich_input: EnrichInput):
    return await enrich(**enrich_input.__dict__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="""Reads a ndjson file from provided input file, extracts IP addresses, and queries Shodan
        for additional information about the IP addresses. By default, data is minified. Writes enriched results 
        to provided output file. Input is expected to be an ndjson file, output will be an ndjson file. Modify 
        the `ip_key` variable to change the key used to extract IP addresses from the input data.
    """
    )
    parser.add_argument(
        "-i",
        "--input",
        help="ndjson file to read results from. Defaults to stdin.",
        type=argparse.FileType("r"),
        default=stdin,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="File to write enriched results to. Defaults to stdout.",
        type=argparse.FileType("w"),
        default=stdout,
    )
    parser.add_argument(
        "-k",
        "--ip_key",
        help="Key to use for IP address. Defaults to 'host'.",
        type=str,
        default="host",
    )
    parser.add_argument(
        "--enrichment-keys",
        nargs="+",
        type=str,
        default=["hostnames", "ports"],
        help="Shodan Keys to include in the enriched output. Use 'all' to include all keys. Defaults to 'hostnames' and 'ports'.",
    )

    minify_group = parser.add_mutually_exclusive_group(required=False)
    minify_group.add_argument(
        "--minify", dest="minify", action="store_true", help="Minify Shodan results."
    )
    minify_group.add_argument(
        "--no-minify",
        dest="minify",
        action="store_false",
        help="Do not minify Shodan results - useful if you want full enrichments.",
    )
    parser.set_defaults(minify=True)
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
        help="Do not use Shodan API key - this may work for some queries.",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=1,
        help="Max requests per second, defaults to 1 (Shodan documentation says this is the max speed)",
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
    query_group = parser.add_mutually_exclusive_group(required=False)
    query_group.add_argument(
        "--internetdb",
        action="store_true",
        help="Use Shodan InternetDB API instead of normal API. Does not require a Shodan API key, but data is less complete and only updated weekly.",
        dest="internetdb",
    )
    query_group.add_argument(
        "--normal",
        action="store_false",
        help="Use normal Shodan API instead of InternetDB API.",
        dest="internetdb",
    )
    parser.set_defaults(internetdb=True)
    args = parser.parse_args()
    return args


async def main():
    args = parse_args()
    if args.quiet:
        logger.setLevel(logging.WARNING)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.debug(f"{args=}")
    if not args.internetdb:
        logger.info("Using normal Shodan API.")
        query_function = fetch_ip
        if args.no_api_key:
            logger.warning(
                "No Shodan API key provided. This may work for some queries."
            )
        else:
            global SHODAN_API_KEY
            load_dotenv()
            SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
            if SHODAN_API_KEY == "":
                raise Exception("SHODAN_API_KEY environment variable is not set.")
    else:
        logger.info("Using Shodan InternetDB API.")
        query_function = fetch_ip_internetdb
    # Grab all input data
    input_data: list[dict] = [json.loads(line) for line in args.input]
    # Convert to EnrichInput
    enrich_inputs: list[EnrichInput] = [
        EnrichInput(
            data=data,
            ip_key=args.ip_key,
            enrichment_keys=args.enrichment_keys,
            minify=args.minify,
            enrichment_function=query_function,
        )
        for data in input_data
    ]
    # Execute tasks with aiometer for rate limiting
    async with aiometer.amap(
        enrich_wrapper,
        enrich_inputs,
        max_per_second=args.rate,
    ) as results:
        async for result in tqdm_asyncio.tqdm(
            results, total=len(enrich_inputs), file=stderr, disable=not args.progress
        ):
            if result:
                args.output.write(json.dumps(result) + "\n")
    await client.aclose()


def run():
    asyncio.run(main())


if __name__ == "__main__":
    asyncio.run(main())
