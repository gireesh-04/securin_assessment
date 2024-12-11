from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

mongo_uri = 'mongodb+srv://gireesh_04:ROWifs5BzMANczn4@cluster0.rfcdd.mongodb.net/NVD_Data'
client = MongoClient(mongo_uri)
db = client.NVD_Data  
cve_collection = db.c_v_e 

@app.route('/api/get_cve_data', methods=['GET'])
def get_cves():
    try:
        
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('limit', 10))
        offset = (page - 1) * per_page

        total = cve_collection.count_documents({})
        cves = list(cve_collection.find().skip(offset).limit(per_page))

        for cve in cves:
            cve['_id'] = str(cve['_id'])  
            if 'cve_id' in cve:
                cve['id'] = cve['cve_id']  
            elif '_id' in cve:
                cve['id'] = str(cve['_id'])

        total_pages = (total + per_page - 1) // per_page

        return jsonify({
            'total': total,
            'page': page,
            'limit': per_page,
            'totalPages': total_pages,
            'cves': cves,
            'has_next': page < total_pages,
            'has_prev': page > 1
        })

    except Exception as error:
        print(f"Error fetching CVEs: {error}")
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/api/get_cve_details', methods=['GET'])
def get_cve():
    try:
        cve_id = request.args.get('id')
        if not cve_id:
            return jsonify({'error': 'CVE ID is required'}), 400

        cve = cve_collection.find_one({'cve_id': cve_id})
        if not cve:
            return jsonify({'error': f'CVE {cve_id} not found in the database'}), 404

        cve['_id'] = str(cve['_id'])

        description_list = cve.get('descriptions', [])
        english_description = next(
            (desc.get('value') for desc in description_list if desc.get('lang') == 'en'),
            'No description available'
        )

        metrics = cve.get('metrics', [])
        cvss_data = metrics[0].get('cvssData', {}) if metrics else {}

        configurations = cve.get('configurations', [])
        extracted_configs = []

        for config in configurations:
            nodes = config.get('nodes', [])
            extracted_nodes = []

            for node in nodes:
                cpe_matches = [
                    {
                        'vulnerable': cpe.get('vulnerable', False),
                        'criteria': cpe.get('criteria', 'N/A'),
                        'matchCriteriaId': cpe.get('matchCriteriaId', 'N/A')
                    }
                    for cpe in node.get('cpeMatch', [])
                ]

                extracted_nodes.append({
                    'operator': node.get('operator', 'N/A'),
                    'negate': node.get('negate', False),
                    'cpeMatch': cpe_matches
                })

            extracted_configs.append({'nodes': extracted_nodes})

        response = {
            'id': cve.get('cve_id', 'N/A'),
            'sourceIdentifier': cve.get('sourceIdentifier', 'N/A'),
            'published': cve.get('published', 'N/A'),
            'lastModified': cve.get('lastModified', 'N/A'),
            'vulnStatus': cve.get('vulnStatus', 'N/A'),
            'descriptions': [{'value': english_description}],
            'cvss': {
                'version': cvss_data.get('version', 'N/A'),
                'vectorString': cvss_data.get('vectorString', 'N/A'),
                'accessVector': cvss_data.get('accessVector', 'N/A'),
                'accessComplexity': cvss_data.get('accessComplexity', 'N/A'),
                'authentication': cvss_data.get('authentication', 'N/A'),
                'confidentialityImpact': cvss_data.get('confidentialityImpact', 'N/A'),
                'integrityImpact': cvss_data.get('integrityImpact', 'N/A'),
                'availabilityImpact': cvss_data.get('availabilityImpact', 'N/A'),
                'baseScore': cvss_data.get('baseScore','N/A'),
                'baseSeverity': metrics[0].get('baseSeverity', 'N/A'),
                'exploitabilityScore': metrics[0].get('exploitabilityScore', 'N/A'),
                'impactScore': metrics[0].get('impactScore', 'N/A')
            },
            'configurations': extracted_configs
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500



if __name__ == '__main__':
    app.run(port = 8000, debug=True)

