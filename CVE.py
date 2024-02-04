class CVE:
    def __init__(self, cve_id="", source_identifier="", published_date="", last_modified_date="", status="",
                 description="", references=None, configurations=None, weaknesses=None, v20_base_severity="",
                 v20_base_score="", v20_vector_string="", v20_exploitability_score="", v20_impact_score="",
                 v30_exploitability_score="", v30_impact_score="", v30_base_severity="", v30_base_score="",
                 v30_vector_string="", v31_base_score="", v31_base_severity="", v31_vector_string="",
                 v31_exploitability_score="", v31_impact_score="", code_snippet=None,):
        self.cve_id = cve_id
        self.source_identifier = source_identifier
        self.published_date = published_date
        self.last_modified_date = last_modified_date
        self.status = status
        self.description = description
        self.references = references if references is not None else []
        self.configurations = configurations if configurations is not None else []
        self.weaknesses = weaknesses if weaknesses is not None else []
        self.v20_base_severity = v20_base_severity
        self.v20_base_score = v20_base_score
        self.v20_vector_string = v20_vector_string
        self.v20_exploitability_score = v20_exploitability_score
        self.v20_impact_score = v20_impact_score
        self.v30_exploitability_score = v30_exploitability_score
        self.v30_impact_score = v30_impact_score
        self.v30_base_severity = v30_base_severity
        self.v30_base_score = v30_base_score
        self.v30_vector_string = v30_vector_string
        self.v31_base_score = v31_base_score
        self.v31_base_severity = v31_base_severity
        self.v31_vector_string = v31_vector_string
        self.v31_exploitability_score = v31_exploitability_score
        self.v31_impact_score = v31_impact_score
        self.code_snippet = code_snippet if code_snippet is not None else []

    def __str__(self):
        return f"ID: {self.cve_id}\n" \
               f"Source Identifier: {self.source_identifier}\n" \
               f"Published Date: {self.published_date}\n" \
               f"Last Modified Date: {self.last_modified_date}\n" \
               f"Status: {self.status}\n" \
               f"Description: {self.description}\n" \
               f"References: {self.references}\n" \
               f"Configurations: {self.configurations}\n" \
               f"Weaknesses: {self.weaknesses}\n" \
               f"V2.0 Base Severity: {self.v20_base_severity}\n" \
               f"V2.0 Base Score: {self.v20_base_score}\n" \
               f"V2.0 Vector String: {self.v20_vector_string}\n" \
               f"V2.0 Exploitability Score: {self.v20_exploitability_score}\n" \
               f"V2.0 Impact Score: {self.v20_impact_score}\n" \
               f"V3.0 Exploitability Score: {self.v30_exploitability_score}\n" \
               f"V3.0 Impact Score: {self.v30_impact_score}\n" \
               f"V3.0 Base Severity: {self.v30_base_severity}\n" \
               f"V3.0 Base Score: {self.v30_base_score}\n" \
               f"V3.0 Vector String: {self.v30_vector_string}\n" \
               f"V3.1 Base Score: {self.v31_base_score}\n" \
               f"V3.1 Base Severity: {self.v31_base_severity}\n" \
               f"V3.1 Vector String: {self.v31_vector_string}\n" \
               f"V3.1 Exploitability Score: {self.v31_exploitability_score}\n" \
               f"V3.1 Impact Score: {self.v31_impact_score}\n"\
               f"Code Snippet: {self.code_snippet}\n"

    # convert to json
    def to_json(self):
        return {
            "id": self.cve_id,
            "source_identifier": self.source_identifier,
            "published_date": self.published_date,
            "last_modified_date": self.last_modified_date,
            "status": self.status,
            "description": self.description,
            "references": self.references,
            "configurations": self.configurations,
            "weaknesses": self.weaknesses,
            "v20_base_severity": self.v20_base_severity,
            "v20_base_score": self.v20_base_score,
            "v20_vector_string": self.v20_vector_string,
            "v20_exploitability_score": self.v20_exploitability_score,
            "v20_impact_score": self.v20_impact_score,
            "v30_base_severity": self.v30_base_severity,
            "v30_base_score": self.v30_base_score,
            "v30_vector_string": self.v30_vector_string,
            "v30_exploitability_score": self.v30_exploitability_score,
            "v30_impact_score": self.v30_impact_score,
            "v31_base_severity": self.v31_base_severity,
            "v31_base_score": self.v31_base_score,
            "v31_vector_string": self.v31_vector_string,
            "v31_exploitability_score": self.v31_exploitability_score,
            "v31_impact_score": self.v31_impact_score,
            "code_snippet": self.code_snippet
        }
