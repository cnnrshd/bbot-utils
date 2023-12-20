# Enriches JSONL input with "cvss" score from NVD
# Expects each line of input to have a "cve" key
# Will add a "cvss3_score" and "cvss3_vector" key to each line of output
import httpx
from dotenv import load_dotenv
import os
from typer import FileTextWrite, FileText, Option, Typer
from typing import Annotated
from sys import stdin, stdout
from functools import lru_cache
from pydantic import BaseModel
import logging
from time import sleep
import json
import tqdm

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)


load_dotenv()
app = Typer()
NVD_API_KEY = os.environ["NVD_API_KEY"]

client: httpx.Client = httpx.Client()


class CVEReturn(BaseModel):
    cvss3_score: float
    cvss3_vector: str


@lru_cache(maxsize=2000)
def lookup_cve(cve_id: str):
    # Sleep inside the cve lookup function
    # limit for nvd is 50 requests in a rolling 30 second window
    # a request every .6 seconds - sleep for 0.75
    sleep(0.75)
    resp = client.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        headers={"apiKey": NVD_API_KEY},
    )
    if resp.status_code == 200:
        json = resp.json()
        # vulnerabilities : list[dict]
        # care about [0]
        if vulnerabilities := json.get("vulnerabilities"):
            if metrics := vulnerabilities[0].get("cve").get("metrics"):
                ret = {
                    "cvss_v3_string": "",
                    "cvss_v3_base_score": 0.0,
                    "cvss_v3_exploitability": 0.0,
                    "cvss_v3_base_severity": "UNKNOWN",
                    "cvss_v2_string": "",
                    "cvss_v2_base_score": 0.0,
                    "cvss_v2_exploitability": 0.0,
                    "cvss_v2_base_severity": "UNKNOWN",
                }
                if "cvssMetricV31" in metrics.keys():
                    m = metrics["cvssMetricV31"][0]
                    ret["cvss_v3_string"] = m.get("cvssData").get("vectorString")
                    ret["cvss_v3_base_score"] = m.get("cvssData").get("baseScore")
                    ret["cvss_v3_exploitability"] = m.get("exploitability")
                    ret["cvss_v3_base_severity"] = m.get("cvssData").get("baseSeverity")
                if "cvssMetricV2" in metrics.keys():
                    m = metrics["cvssMetricV2"][0]
                    ret["cvss_v2_string"] = m.get("cvssData").get("vectorString")
                    ret["cvss_v2_base_score"] = m.get("cvssData").get("baseScore")
                    ret["cvss_v2_exploitability"] = m.get("exploitability")
                    ret["cvss_v2_base_severity"] = m.get("baseSeverity")
                return ret

        logger.warning(f"Invalid CVE_ID {cve_id} no response returned ")
    logger.error(f"Unexpected response from NVD: {resp.status_code}\t{resp.text}")


@app.command()
def main(
    input_file: Annotated[FileText, Option(help="File to read input from")] = stdin,
    output_file: Annotated[
        FileTextWrite, Option(help="File to write output to")
    ] = stdout,
):
    for line in tqdm.tqdm(input_file, desc="Processing CVEs"):
        data: dict = json.loads(line)
        if "cve" in data.keys():
            cve_info = lookup_cve(data["cve"])
            if cve_info:
                data.update(cve_info)
                output_file.write(f"{json.dumps(data, indent=None)}\n")
            else:
                logger.warning(f"No return for {data['cve']}")
        else:
            logger.warning(f"Skipping improperly-formatted input {data=}")


if __name__ == "__main__":
    app()
