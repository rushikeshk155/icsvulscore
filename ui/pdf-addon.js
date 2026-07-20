/**
 * ICS Risk Auditor PDF Export Engine Add-on
 * Updated with strict type-casting to catch both string and numeric risk scores.
 */

let myPdfChart = null;

function exportAuditPDF() {
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

        // 🚨 CRITICAL DATA NORMALIZATION: Check both potential keys and force them into float numbers
        const normalizedData = resultsData.map(r => {
            const rawScore = r.Risk_Score !== undefined ? r.Risk_Score : (r.cvss_score !== undefined ? r.cvss_score : 0);
            const rawCve = r.Max_CVE_ID || r.cve_id || 'NONE';
            const rawAsset = r.Asset_ID || null;
            const rawMake = r.Make || '';
            const rawModel = r.Model || '';
            
            return {
                assetId: rawAsset,
                makeModel: rawMake || rawModel ? `${rawMake} ${rawModel}`.trim() : 'Scan Match',
                cveId: rawCve,
                score: parseFloat(rawScore) || 0
            };
        });

        // Compute Summaries accurately using normalized numbers
        const totalAssets = normalizedData.length;
        const maxScore = Math.max(...normalizedData.map(d => d.score));
        const criticalCount = normalizedData.filter(d => d.score >= 7.0).length;
        const lowMediumCount = totalAssets - criticalCount;

        // Hydrate Document Metadata
        let activeUsername = "Operator";
        if (typeof currentUser !== 'undefined' && currentUser && currentUser.username) {
            activeUsername = currentUser.username;
        }

        document.getElementById('pdf-meta-user').innerText = `User: ${activeUsername}`;
        document.getElementById('pdf-meta-date').innerText = `Date: ${new Date().toLocaleDateString()}`;
        document.getElementById('pdf-stat-total').innerText = totalAssets;
        document.getElementById('pdf-stat-max').innerText = maxScore.toFixed(1);

        // Rebuild Table Rows mapping exactly to the UI display states
        const tbody = document.getElementById('pdfTableBody');
        tbody.innerHTML = "";
        
        normalizedData.forEach((d, index) => {
            let scoreClass = d.score >= 7.0 ? "text-red-400 font-bold" : "text-slate-300";
            let displayName = d.assetId ? `<strong>${d.assetId}</strong>` : `<strong>Asset #${index + 1}</strong>`;
            
            tbody.innerHTML += `
                <tr class="border-t border-slate-800/40 text-[11px]">
                    <td class="p-3">${displayName}<br><span class="text-[9px] text-slate-500">${d.makeModel}</span></td>
                    <td class="p-3 text-center font-mono text-slate-400">${d.cveId}</td>
                    <td class="p-3 text-center font-mono ${scoreClass}">${d.score > 0 ? d.score.toFixed(1) : '0'}</td>
                </tr>
            `;
        });

        // Initialize Canvas Chart Instance with updated metrics
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

        // Generate the Layout
        setTimeout(() => {
            const configOptions = {
                margin:       [10, 10, 10, 10],
                filename:     `ICS_Vulnerability_Report_${new Date().toISOString().slice(0,10)}.pdf`,
                image:        { type: 'jpeg', quality: 0.98 },
                html2canvas:  { scale: 2, useCORS: true, backgroundColor: '#0b1120' },
                jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
            };

            html2pdf().set(configOptions).from(reportElement).save().then(() => {
                parentWrapper.classList.add('hidden');
                parentWrapper.style.position = '';
            }).catch((err) => {
                console.error("PDF generation error:", err);
                parentWrapper.classList.add('hidden');
            });
            
        }, 400);

    } catch (globalError) {
        console.error("PDF Engine Crash Log:", globalError);
        alert(`Failed to compile PDF: ${globalError.message}`);
        parentWrapper.classList.add('hidden');
    }
}
