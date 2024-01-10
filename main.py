import os

from nvd_api import NvdApiClient

API_KEY = os.getenv('API_KEY')
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
    data = crawl(num_cves, from_index)
    print('Crawling finished')
    # print(data[0])
    print('Preprocessing...')  # preprocess(data)


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
            data.append(cve.cve)
        if num_cves:
            num_cves -= len(response.vulnerabilities)
            if num_cves <= 0:
                break
        else:
            if len(response.vulnerabilities) < 2000:
                break
        start_index += len(response.vulnerabilities)

    return data


def preprocess(data):
    pass


if __name__ == '__main__':
    main()
