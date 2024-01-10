# NVD-vulnerabilities
- [Plan](https://docs.google.com/document/d/1-yHempHQgdhwTyNKZZ4Ld_x5NPwzRSLyRiWn0T8ZbEU/edit)
- Install requirements: `pip install -r requirements.txt`
- Get an API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key)
- Create a .env file in the root directory and add the following line:
```API_KEY=<your api key>```
  - Workaround: issue when crawl reference URLs
      - Locate the `nvd-api` library installation folder: `pip show nvd-api`
      - Locate to file `low_api/model/cve_oas_vulnerabilities_inner_cve_references_inner.py`
      - In line 62
  
    ```
    validations = {
        ('url',): {
            'max_length': 500,  # Set maximum length for the URL
            'regex': {
                'pattern': r'^(ftp|http)s?:\/\/\S+$',  # Set regex pattern for URL validation
            },
        },
    }
    ```
      change the pattern to

    ```
                'pattern': r'^(ftp|http|ttp)s?:\/\/\S+$'
    ```
- Run the script: `python3 main.py`
