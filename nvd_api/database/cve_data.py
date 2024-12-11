from flask import Flask
from datetime import datetime
import requests
from cve_data_format import CVE, CvssMetricV2, CvssData, Description, Configuration, Node
from mongoengine import connect, disconnect

app = Flask(__name__)

MONGO_URI = 'mongodb+srv://gireesh_04:ROWifs5BzMANczn4@cluster0.rfcdd.mongodb.net/NVD_Data'
connect(host=MONGO_URI)  

def format_date(date_str):
    try:
        date_obj = datetime.strptime(date_str[:10], "%Y-%m-%d")
        return date_obj.strftime("%d %b %Y")
    except Exception as e:
        print(f"Date formatting error: {e}")
        return None

def transform_descriptions(descriptions):
    return [Description(lang=desc["lang"], value=desc["value"]) for desc in descriptions]

def transform_cvss_metrics(metrics):
    cvss_metrics_v2 = []
    if 'cvssMetricV2' in metrics:
        for metric in metrics['cvssMetricV2']:
            cvss_metrics_v2.append(CvssMetricV2(
                source=metric['source'],
                type=metric['type'],
                cvssData=CvssData(
                    version=metric['cvssData']['version'],
                    vectorString=metric['cvssData']['vectorString'],
                    accessVector=metric['cvssData']['accessVector'],
                    accessComplexity=metric['cvssData']['accessComplexity'],
                    authentication=metric['cvssData']['authentication'],
                    confidentialityImpact=metric['cvssData']['confidentialityImpact'],
                    integrityImpact=metric['cvssData']['integrityImpact'],
                    availabilityImpact=metric['cvssData']['availabilityImpact'],
                    baseScore=metric['cvssData']['baseScore']
                ),
                baseSeverity=metric['baseSeverity'],
                exploitabilityScore=metric['exploitabilityScore'],
                impactScore=metric['impactScore'],
                acInsufInfo=metric['acInsufInfo'],
                obtainAllPrivilege=metric['obtainAllPrivilege'],
                obtainUserPrivilege=metric['obtainUserPrivilege'],
                obtainOtherPrivilege=metric['obtainOtherPrivilege'],
                userInteractionRequired=metric['userInteractionRequired']
            ))
    return cvss_metrics_v2

def transform_configurations(configurations):
    transformed_configs = []
    
    if configurations and isinstance(configurations, list):
        for configuration in configurations:
            if 'nodes' in configuration and isinstance(configuration['nodes'], list):
                for node in configuration['nodes']:
                    # Extract cpeMatch details including vulnerable, criteria, and matchCriteriaId
                    cpe_matches = [
                        {
                            'vulnerable': cpe.get('vulnerable', False),
                            'criteria': cpe.get('criteria', ''),
                            'matchCriteriaId': cpe.get('matchCriteriaId', '')
                        }
                        for cpe in node.get('cpeMatch', [])
                        if 'criteria' in cpe
                    ]
        
                    transformed_node = Node(
                        operator=node.get('operator', ''),
                        negate=node.get('negate', False),
                        cpeMatch=cpe_matches  
                    )
                    
                    transformed_configs.append(Configuration(nodes=[transformed_node]))
    return transformed_configs




def store_cves():
    results_per_page = 20
    start_index = 0
    total_results = 20

    try:
        while start_index < total_results:
            print(f"Fetching CVEs starting from index {start_index}")
            response = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start_index}&resultsPerPage={results_per_page}"
            )
            response.raise_for_status()

            vulnerabilities = response.json().get('vulnerabilities', [])
            if not vulnerabilities:
                print("No more vulnerabilities to fetch.")
                break

            for vulnerability in vulnerabilities:
                cve_data = vulnerability['cve']
                try:
                    # Check if CVE already exists in the database
                    existing_cve = CVE.objects(cve_id=cve_data['id']).first()
                    if not existing_cve:
                        cve_document = CVE(
                            cve_id=cve_data['id'],
                            sourceIdentifier=cve_data['sourceIdentifier'],
                            published=format_date(cve_data['published']),
                            lastModified=format_date(cve_data['lastModified']),
                            vulnStatus=cve_data['vulnStatus'],
                            descriptions=transform_descriptions(cve_data['descriptions']),
                            metrics=transform_cvss_metrics(cve_data.get('metrics', {})),
                            configurations=transform_configurations(cve_data.get('configurations', {}))
                        )
                        cve_document.save()
                        print(f"Stored CVE: {cve_data['id']}")
                    else:
                        print(f"Duplicate CVE found: {cve_data['id']}, skipping...")

                except Exception as e:
                    print(f"Error saving CVE {cve_data['id']}: {e}")

            start_index += results_per_page

    except Exception as e:
        print(f"Error fetching CVEs: {e}")

    finally:
        disconnect()


@app.route('/store-cves', methods=['GET'])
def trigger_store():
    store_cves()
    return "CVEs stored successfully!"

if __name__ == '__main__':
    print(app.url_map)  # Debugging: Print registered routes
    app.run(port=5000, debug=True)