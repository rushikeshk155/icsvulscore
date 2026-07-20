/**
 * ICS Risk Auditor PDF Export Engine Add-on
 * Updated to match the backend D1 database column naming conventions.
 */

let myPdfChart = null;

function exportAuditPDF() {
    // 1. Check if data exists (handling both resultsData array or standard array format)
    if (typeof resultsData === 'undefined' || resultsData.length === 0) {
        return alert("No calculated rows available to print. Please run the audit scan first.");
    }

    const reportElement = document.getElementById('pdf-report-layout');
    if (!reportElement) return alert("Error: PDF report element template missing from DOM.");
    const parentWrapper = reportElement.parentElement;

    try {
        // Render off-screen temporarily so elements maintain width/height measurements
        parentWrapper.classList.remove('hidden');
        parentWrapper.style.position = 'fixed';
        parentWrapper.style.left = '-9999px';
        parentWrapper.style.top = '0';
        parentWrapper.style.zIndex = '-9999';

        // 2. Compute Data Summaries using actual DB properties: 'cvss_score'
        const totalAssets = resultsData.length;
        const maxScore = Math.max(...resultsData.map(r => r.cvss_score || 0));
        const criticalCount = resultsData.filter(r => (r.cvss_score || 0) >= 7).length;
        const lowMediumCount = totalAssets - criticalCount;

        // 3. Hydrate Document Metadata
        let activeUsername = "Operator";
        if (typeof currentUser !== 'undefined' && currentUser && currentUser.username) {
            activeUsername = currentUser.username;
        }

        document.getElementById('pdf-meta-user').innerText = `User: ${activeUsername}`;
        document.getElementById('pdf-meta-date').innerText = `Date: ${new Date().toLocaleDateString()}`;
        document.getElementById('pdf-stat-total').innerText = totalAssets;
        document.getElementById('pdf-stat-max').innerText = maxScore.toFixed(1);

        // 4. Rebuild Table Rows mapping to 'cve_id' and 'cvss_score'
        const tbody = document.getElementById('pdfTableBody');
        tbody.innerHTML = "";
        
        resultsData.forEach((r, index) => {
            const score = r.cvss_score || 0;
            let scoreClass = score >= 7 ? "text-red-400 font-bold" : "text-slate-300";
            
            tbody.innerHTML += `
                <tr class="border-t border-slate-800/40 text-[11px]">
                    <td class="p-3"><strong>Asset #${index + 1}</strong><br><span class="text-[9px] text-slate-500">Scan Match</span></td>
                    <td class="p-3 text-center font-mono text-slate-400">${r.cve_id || 'NONE'}</td>
                    <td class="p-3 text-center font-mono ${scoreClass}">${score > 0 ? score : '0'}</td>
                </tr>
            `;
        });

        // 5. Initialize Canvas Chart Instance
        if (myPdfChart) { myPdfChart.destroy(); }
        
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
                animation: false,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 10 } } }
                }
            }
        });

        // 6. Generate the Document Layout
        setTimeout(() => {
            const configOptions = {
                margin:       [10, 10, 10, 10],
                filename:     `ICS_Vulnerability_Report_${new Date().toISOString().slice(0,10)}.pdf`,
                image:        { type: 'jpeg', quality: 0.98 },
                html2canvas:  { scale: 2, useCORS: true, backgroundColor: '#0b1120' },
                jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
            };

            html2pdf().set(configOptions).from(reportElement).save().then(() => {
                // Re-hide completely once execution concludes
                parentWrapper.classList.add('hidden');
                parentWrapper.style.position = '';
            }).catch((err) => {
                console.error("PDF generation engine processing failure:", err);
                parentWrapper.classList.add('hidden');
            });
            
        }, 400);

    } catch (globalError) {
        console.error("PDF Engine Crash Log:", globalError);
        alert(`Failed to compile PDF: ${globalError.message}`);
        parentWrapper.classList.add('hidden');
    }
}
