let currentPage = 1;
let perPage = 10;
let totalPages = 200;

async function fetchCVEs() {
  document.getElementById('loading').style.display = 'block';
  document.getElementById('error').style.display = 'none';

  try {
    const response = await fetch(`http://localhost:8000/api/get_cve_data?page=${currentPage}&limit=${perPage}`);
    if (!response.ok) {
      throw new Error('Failed to fetch data');
    }

    const jsonData = await response.json();

    const tableBody = document.getElementById('cveTableBody');
    tableBody.innerHTML = '';
    jsonData.cves.forEach((cve) => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${cve.id || 'N/A'}</td>
        <td>${cve.sourceIdentifier || 'N/A'}</td>
        <td>${cve.published || 'N/A'}</td>
        <td>${cve.lastModified || 'N/A'}</td>
        <td>${cve.vulnStatus || 'N/A'}</td>
      `;
      row.onclick = () => {
        window.location.href = `cve_details.html?id=${cve.id}`;
      };
      tableBody.appendChild(row);
    });

    document.getElementById('totalRecords').innerText = `Total Records: ${jsonData.total}`;
    totalPages = jsonData.totalPages;
    document.getElementById('currentPage').innerText = `Page ${jsonData.page} of ${totalPages}`;
    document.getElementById('prevPage').disabled = jsonData.page === 1;
    document.getElementById('nextPage').disabled = jsonData.page === totalPages;

  } catch (error) {
    console.error('Error fetching CVEs:', error);
    document.getElementById('error').style.display = 'block';
  } finally {
    document.getElementById('loading').style.display = 'none';
  }
}

function changePage(pageNumber) {
  if (pageNumber >= 1 && pageNumber <= totalPages) {
    currentPage = pageNumber;
    fetchCVEs();
  }
}

function changePerPage() {
  perPage = parseInt(document.getElementById('perPage').value);
  currentPage = 1;
  fetchCVEs();
}

function showDetails(cve) {
  const detailsContainer = document.getElementById('cveDetails');
  detailsContainer.style.display = 'block';
  detailsContainer.innerHTML = `
    <h1>${cve.id}</h1>
    <h3>Description:</h3>
    <h5>${cve.descriptions[0].value}</h5>
    <h3>CVSS V2 Metrics</h3>
    <h5>Severity: ${cve.metrics.cvssMetricV2[0].baseSeverity}</h5>
    <h5>Vector String: ${cve.metrics.cvssMetricV2[0].cvssData.vectorString}</h5>
    <table class="cve-details-table">
      <thead>
        <tr>
          <th>Access Vector</th>
          <th>Access Complexity</th>
          <th>Authentication</th>
          <th>Confidentiality Impact</th>
          <th>Integrity Impact</th>
          <th>Availability Impact</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>${cve.metrics.cvssMetricV2[0].cvssData.accessVector}</td>
          <td>${cve.metrics.cvssMetricV2[0].cvssData.accessComplexity}</td>
          <td>${cve.metrics.cvssMetricV2[0].cvssData.authentication}</td>
          <td>${cve.metrics.cvssMetricV2[0].cvssData.confidentialityImpact}</td>
          <td>${cve.metrics.cvssMetricV2[0].cvssData.integrityImpact}</td>
          <td>${cve.metrics.cvssMetricV2[0].cvssData.availabilityImpact}</td>
        </tr>
      </tbody>
    </table>
  `;
}

fetchCVEs();