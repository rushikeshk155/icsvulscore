/**
 * ICS Risk Auditor PDF Export Engine Add-on
 * Handles runtime chart parsing, DOM hydration, and multi-page compilation.
 */

let myPdfChart = null; // Scoped variable to manage Chart lifecycle states safely

function exportAuditPDF() {
    if (typeof resultsData === 'undefined' || resultsData.length === 0) {
        return alert("No calculated rows available to print.");
    }

    // 1. Compute Data Summaries and Risk Distributions
    const totalAssets = resultsData.length;
    const maxScore = Math.max(...resultsData.map(r => r.Risk_Score));
    const criticalCount = resultsData.filter(r => r.Risk_Score >= 7).length;
    const lowMediumCount = totalAssets - criticalCount;

    // 2. Hydrate Document Metadata Fields
    document.getElementById('pdf-meta-user').innerText = `User: ${currentUser ? currentUser.username : 'Operator'}`;
    document.getElementById('pdf-meta-date').innerText = `Date: ${new Date().toLocaleDateString()}`;
    document.getElementById('pdf-stat-total').innerText = totalAssets;
    document.getElementById('pdf-stat-max').innerText = maxScore.toFixed(1);

    // 3. Rebuild the Component Threat Grid Rows
    const tbody = document.getElementById('pdfTableBody');
    tbody.innerHTML = "";
    
    resultsData.forEach(r => {
        let scoreClass = r.Risk_Score >= 7 ? "text-red-400 font-bold" : "text-slate-300";
        tbody.innerHTML += `
            <tr class="border-t border-slate-800/40 text-[11px]">
                <td class="p-3"><strong>${r.Asset_ID}</strong><br><span class="text-[9px] text-slate-500">${r.Make} ${r.Model}</span></td>
                <td class="p-3 text-center font-mono text-slate-400">${r.Max_CVE_ID}</td>
                <td class="p-3 text-center font-mono ${scoreClass}">${r.Risk_Score > 0 ? r.Risk_Score : '--'}</td>
            </tr>
        `;
    });

    // 4. Initialize Canvas Canvas Graph Instance
    if (myPdfChart) { 
        myPdfChart.destroy(); 
    }
    
    const ctx = document.getElementById('pdfDistributionChart').getContext('2d');
    myPdfChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Critical/High Risk', 'Low/Medium Risk'],
            datasets: [{
                data: [criticalCount, lowMediumCount],
                backgroundColor: ['#ef4444', '#3b82f6'],
                borderColor: '#0f172a',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { 
                    position: 'bottom', 
                    labels: { color: '#94a3b8', font: { size: 10 } } 
                }
            }
        }
    });

    // 5. Allow rendering engine to execute frames before snapshotting
    setTimeout(() => {
        const reportElement = document.getElementById('pdf-report-layout');
        
        const configOptions = {
            margin:       [10, 10, 10, 10],
            filename:     `ICS_Vulnerability_Report_${new Date().toISOString().slice(0,10)}.pdf`,
            image:        { type: 'jpeg', quality: 0.98 },
            html2canvas:  { scale: 2, useCORS: true, backgroundColor: '#0b1120' },
            jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
        };

        // Render target layout element structure to output PDF
        html2pdf().set(configOptions).from(reportElement).save();
    }, 800);
}
