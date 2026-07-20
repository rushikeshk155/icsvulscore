/**
 * ICS Risk Auditor PDF Export Engine Add-on
 * Professional Enterprise Layout with Detailed D1 Threat Intelligence Strings
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

        // 1. Normalize and Enrich Data utilizing all available D1 fields
        const normalizedData = resultsData.map(r => {
            const rawScore = r.Risk_Score !== undefined ? r.Risk_Score : (r.cvss_score !== undefined ? r.cvss_score : 0);
            const rawCve = r.Max_CVE_ID || r.cve_id || 'NONE';
            const scoreNum = parseFloat(rawScore) || 0;
            
            // Extract rich metadata from D1 table output
            const description = r.description || 'No public exploit description available in localized database.';
            const status = r.vuln_status || 'ANALYZED';

            return {
                assetId: r.Asset_ID || 'Unknown Hardware',
                make: r.Make || '',
                model: r.Model || '',
                firmware: r.Firmware || r.firmware || 'N/A',
                cveId: rawCve,
                score: scoreNum,
                description: description,
                status: status
            };
        });

        // 2. Compute Summaries accurately
        const totalAssets = normalizedData.length;
        const maxScore = Math.max(...normalizedData.map(d => d.score));
        const criticalCount = normalizedData.filter(d => d.score >= 7.0).length;
        const lowMediumCount = totalAssets - criticalCount;

        // 3. Hydrate Document Metadata Headers
        let activeUsername = "Operator";
        if (typeof currentUser !== 'undefined' && currentUser && currentUser.username) {
            activeUsername = currentUser.username;
        }

        document.getElementById('pdf-meta-user').innerText = `User: ${activeUsername}`;
        document.getElementById('pdf-meta-date').innerText = `Date: ${new Date().toLocaleDateString()}`;
        document.getElementById('pdf-stat-total').innerText = totalAssets;
        document.getElementById('pdf-stat-max').innerText = maxScore.toFixed(1);

        // 4. Rebuild Table Rows with Executive UX Enhancements
        const tbody = document.getElementById('pdfTableBody');
        tbody.innerHTML = "";
        
        normalizedData.forEach((d) => {
            // Determine styling badges based on metrics
            let severityBadge = "";
            let scoreColor = "";
            if (d.score >= 9.0) {
                severityBadge = `<span class="bg-red-500/20 text-red-400 border border-red-500/30 text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider">Critical</span>`;
                scoreColor = "text-red-400 font-extrabold";
            } else if (d.score >= 7.0) {
                severityBadge = `<span class="bg-orange-500/20 text-orange-400 border border-orange-500/30 text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider">High</span>`;
                scoreColor = "text-orange-400 font-bold";
            } else if (d.score >= 4.0) {
                severityBadge = `<span class="bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 text-[9px] px-1.5 py-0.5 rounded font-semibold uppercase tracking-wider">Medium</span>`;
                scoreColor = "text-yellow-400";
            } else {
                severityBadge = `<span class="bg-slate-500/20 text-slate-400 border border-slate-500/30 text-[9px] px-1.5 py-0.5 rounded font-medium uppercase tracking-wider">Low</span>`;
                scoreColor = "text-slate-400";
            }
            
            tbody.innerHTML += `
                <tr class="border-t border-slate-800/60 bg-slate-900/10 text-[11px] hover:bg-slate-900/30 transition-colors">
                    <td class="p-3 align-top leading-relaxed w-[30%]">
                        <div class="text-slate-200 font-bold text-xs">${d.assetId}</div>
                        <div class="text-[10px] text-slate-400 font-medium">${d.make} ${d.model}</div>
                        <div class="text-[9px] text-slate-500 font-mono mt-0.5">FW: ${d.firmware}</div>
                    </td>
                    <td class="p-3 align-top w-[55%] text-left">
                        <div class="flex items-center gap-2 mb-1">
                            <span class="font-mono text-xs font-semibold text-sky-400 tracking-tight">${d.cveId}</span>
                            ${severityBadge}
                            <span class="text-[8px] text-slate-500 font-mono px-1 border border-slate-800 rounded bg-slate-950">${d.status}</span>
                        </div>
                        <p class="text-[10px] text-slate-400 leading-normal line-clamp-3 italic">
                            "${d.description}"
                        </p>
                    </td>
                    <td class="p-3 align-top text-center font-mono text-sm ${scoreColor} w-[15%] font-bold">
                        ${d.score > 0 ? d.score.toFixed(1) : '0.0'}
                    </td>
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

        // 6. Generate Layout Compilation Parameters
        setTimeout(() => {
            const configOptions = {
                margin:       [12, 12, 12, 12],
                filename:     `ICS_Vulnerability_Report_${new Date().toISOString().slice(0,10)}.pdf`,
                image:        { type: 'jpeg', quality: 0.99 },
                html2canvas:  { scale: 2, useCORS: true, backgroundColor: '#0b1120' },
                jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
            };

            html2pdf().set(configOptions).from(reportElement).save().then(() => {
                parentWrapper.classList.add('hidden');
                parentWrapper.style.position = '';
            }).catch((err) => {
                console.error("PDF generation pipeline failure:", err);
                parentWrapper.classList.add('hidden');
            });
            
        }, 400);

    } catch (globalError) {
        console.error("PDF Engine Crash Log:", globalError);
        alert(`Failed to compile PDF: ${globalError.message}`);
        parentWrapper.classList.add('hidden');
    }
}
