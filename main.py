import csv
import json
import os

from dotenv import load_dotenv
from nvd_api import NvdApiClient

from CVE import CVE

load_dotenv()
API_KEY = os.environ.get('API_KEY')
client = NvdApiClient(wait_time=1000, api_key=API_KEY)


def main():
    print('Welcome to NVD Data Crawler')
    print('How many CVEs do you want to crawl? (default: all)')
    try:
        num_cves = int(input())
    except ValueError:
        num_cves = None
    print('Which index do you want to start from? (default: 0)')
    try:
        from_index = int(input())
    except ValueError:
        from_index = 0

    print('Crawling...')
    raw_data = crawl(num_cves, from_index)

    print('Crawling finished')
    data = export_to_json(raw_data)
    print('Exporting to json...')
    save_to_json('data.json', data)
    print('Exporting to csv...')
    save_to_csv('data.csv', data)



def extract_info(crawled_data):
    cve = CVE()
    cve.cve_id = crawled_data.id
    for description in crawled_data.descriptions:
        if description.lang == 'en':
            cve.description = description.value
            break
    cve.source_identifier = crawled_data.source_identifier
    cve.status = crawled_data.vuln_status
    cve.published_date = crawled_data.published.date().strftime("%Y-%m-%d")
    cve.last_modified_date = crawled_data.last_modified.date().strftime("%Y-%m-%d")
    for ref in crawled_data.references:
        cve.references.append(ref.url)
    if hasattr(crawled_data, 'weaknesses'):
        for weakness in crawled_data.weaknesses:
            for description in weakness.description:
                if description.lang == 'en':
                    cve.weaknesses.append(description.value)
                    break
    if hasattr(crawled_data, 'configurations'):
        for config in crawled_data.configurations:
            for node in config.nodes:
                for cpe in node.cpe_match:
                    cve.configurations.append(cpe.criteria)
    if hasattr(crawled_data, 'metrics'):
        if hasattr(crawled_data.metrics, 'cvss_metric_v2'):
            v2_metrics = crawled_data.metrics.cvss_metric_v2[0]
            if hasattr(v2_metrics, 'base_severity'):
                cve.v20_base_severity = v2_metrics.base_severity
            if hasattr(v2_metrics, 'exploitability_score'):
                cve.v20_exploitability_score = v2_metrics.exploitability_score
            if hasattr(v2_metrics, 'impact_score'):
                cve.v20_impact_score = v2_metrics.impact_score
            if hasattr(v2_metrics, 'cvss_data'):
                if hasattr(v2_metrics.cvss_data, 'base_score'):
                    cve.v20_base_score = v2_metrics.cvss_data.base_score
                if hasattr(v2_metrics.cvss_data, 'vector_string'):
                    cve.v20_vector_string = v2_metrics.cvss_data.vector_string
        if hasattr(crawled_data.metrics, 'cvss_metric_v30'):
            v30_metrics = crawled_data.metrics.cvss_metric_v30[0]
            if hasattr(v30_metrics, 'exploitability_score'):
                cve.v30_exploitability_score = v30_metrics.exploitability_score
            if hasattr(v30_metrics, 'impact_score'):
                cve.v30_impact_score = v30_metrics.impact_score
            if hasattr(v30_metrics, 'cvss_data'):
                if hasattr(v30_metrics.cvss_data, 'base_score'):
                    cve.v30_base_score = v30_metrics.cvss_data.base_score
                if hasattr(v30_metrics.cvss_data, 'base_severity'):
                    cve.v30_base_severity = v30_metrics.cvss_data.base_severity
                if hasattr(v30_metrics.cvss_data, 'vector_string'):
                    cve.v30_vector_string = v30_metrics.cvss_data.vector_string
        if hasattr(crawled_data.metrics, 'cvss_metric_v31'):
            v31_metrics = crawled_data.metrics.cvss_metric_v31[0]
            if hasattr(v31_metrics, 'exploitability_score'):
                cve.v31_exploitability_score = v31_metrics.exploitability_score
            if hasattr(v31_metrics, 'impact_score'):
                cve.v31_impact_score = v31_metrics.impact_score
            if hasattr(v31_metrics, 'cvss_data'):
                if hasattr(v31_metrics.cvss_data, 'base_score'):
                    cve.v31_base_score = v31_metrics.cvss_data.base_score
                if hasattr(v31_metrics.cvss_data, 'base_severity'):
                    cve.v31_base_severity = v31_metrics.cvss_data.base_severity
                if hasattr(v31_metrics.cvss_data, 'vector_string'):
                    cve.v31_vector_string = v31_metrics.cvss_data.vector_string
    return cve


def export_to_json(data):
    for i in range(len(data)):
        data[i] = data[i].to_json()
    return data


def crawl(num_cves, from_index):
    start_index = from_index
    data = []
    while True:
        if num_cves:
            results_per_page = 2000 if num_cves > 2000 else num_cves
        else:
            results_per_page = 2000
        response = client.get_cves(results_per_page=results_per_page, start_index=start_index)
        for cve in response.vulnerabilities:
            data.append(extract_info(cve.cve))
        if num_cves:
            num_cves -= len(response.vulnerabilities)
            if num_cves <= 0:
                break
        else:
            if len(response.vulnerabilities) < 2000:
                break
        start_index += len(response.vulnerabilities)

    return data


def save_to_json(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def save_to_csv(file_path, data):
    with open(file_path, 'w', newline='') as file:
        fieldnames = ["id", "source_identifier", "published_date", "last_modified_date", "status", "description",
                      "references", "configurations", "weaknesses", "v20_base_severity", "v20_base_score",
                      "v20_vector_string", "v20_exploitability_score", "v20_impact_score", "v30_base_severity",
                      "v30_base_score", "v30_vector_string", "v30_exploitability_score", "v30_impact_score",
                      "v31_base_severity", "v31_base_score", "v31_vector_string", "v31_exploitability_score",
                      "v31_impact_score"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for i in range(len(data)):
            writer.writerow(data[i])


def preprocess(data):
    pass


if __name__ == '__main__':
    main()
