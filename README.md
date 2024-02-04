# NVD-vulnerabilities
- [Plan](https://docs.google.com/document/d/1-yHempHQgdhwTyNKZZ4Ld_x5NPwzRSLyRiWn0T8ZbEU/edit)
- [Dataset](https://drive.google.com/drive/folders/185LSVVKdfu6BBse_8yQ3sUfiQYsEJqUv?usp=sharing)
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
- Because it takes long time to scrap code from git commit and not all rows have github commit link so if you want to scrap all cves with source code, change branch to 'code' and do same step as above and run 'python3 main.py' 
- User has to provide which index they want to crawl from, and how many CVE that they want to crawl. This is because NVD fulfills crawling requests with an array of CVE, along with the start index and length of array.
- If the crawling process is successful, the data will be saved into the same folder as 2 file csv and json, with timestamp. Users can use these files directly for researching.

