async function fetchCveDetails() {
    const urlParams = new URLSearchParams(window.location.search);
    const cveId = urlParams.get('id'); // Get the CVE ID from the URL
  
    if (!cveId) {
      document.getElementById('cveDetails').innerText = 'CVE ID not provided';
      return;
    }
  
    try {
      const response = await fetch(`http://localhost:8000/api/get_cve_details?id=${cveId}`);
      if (!response.ok) {
        throw new Error('Failed to fetch CVE details');
      }
  
      const cve = await response.json();
  
      document.getElementById('cveDetails').innerHTML = `
        <h2>${cve.id}</h2>
        <p><strong>Description:</strong> ${cve.descriptions[0]?.value || 'N/A'}</p>
  
        <div class="section-title">CVSS Metrics:</div>
        <p><strong>Severity:</strong> ${cve.cvss?.baseSeverity || 'N/A'}  <strong>Score:</strong> ${cve.cvss?.baseScore || 'N/A'}</p>
        <p><strong>Vector String:</strong> ${cve.cvss?.vectorString || 'N/A'}</p>
  
        <table>
          <tr>
            <th>Access Vector</th>
            <th>Access Complexity</th>
            <th>Authentication</th>
            <th>Confidentiality Impact</th>
            <th>Integrity Impact</th>
            <th>Availability Impact</th>
          </tr>
          <tr>
            <td>${cve.cvss?.accessVector || 'N/A'}</td>
            <td>${cve.cvss?.accessComplexity || 'N/A'}</td>
            <td>${cve.cvss?.authentication || 'N/A'}</td>
            <td>${cve.cvss?.confidentialityImpact || 'N/A'}</td>
            <td>${cve.cvss?.integrityImpact || 'N/A'}</td>
            <td>${cve.cvss?.availabilityImpact || 'N/A'}</td>
          </tr>
        </table>
  
        <div class="section-title">SCORE:</div>
        <p><strong>Exploitability Score:</strong> ${cve.cvss?.exploitabilityScore || 'N/A'}</p>
        <p><strong>Impact Score:</strong> ${cve.cvss?.impactScore || 'N/A'}</p>
        ${cve.configurations?.map((config, index) => `
          <div class="node-section">
            ${config.nodes?.map(node => `
              <div class="section-title">CPE</div>
              <table>
                <tr>
                  <th>Criteria</th>
                  <th>Match Criteria ID</th>
                  <th>Vulnerable</th>
                </tr>
                ${node.cpeMatch?.map(cpeItem => `
                  <tr>
                    <td>${cpeItem.criteria || 'N/A'}</td>
                    <td>${cpeItem.matchCriteriaId || 'N/A'}</td>
                    <td>${cpeItem.vulnerable ? 'Yes' : 'No'}</td>
                  </tr>
                `).join('') || '<tr><td colspan="3">No CPE Match data available</td></tr>'}
              </table>
            `).join('') || '<p>No nodes available</p>'}
          </div>
        `).join('') || '<p>No configuration data available</p>'}
      `;
    } catch (error) {
      document.getElementById('cveDetails').innerText = 'Error fetching CVE details';
    }
  }
  
  // Fetch details on page load
  fetchCveDetails();
  