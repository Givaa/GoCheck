"""
Report Generators for GoCheck
Generates HTML, JSON, and Markdown reports from analysis results.

Author: @Givaa
"""

import json
from datetime import datetime
from typing import List, Dict, Any
import os


class HTMLReportGenerator:
    """Generate interactive HTML report with statistics and detailed breakdowns."""

    def __init__(self, results: List[Dict], human_report: List[Dict], campaign_name: str = "GoPhish Campaign"):
        """
        Initialize HTML report generator.

        Args:
            results: Complete analysis results
            human_report: Human-focused report
            campaign_name: Campaign name for the report title
        """
        self.results = results
        self.human_report = human_report
        self.campaign_name = campaign_name
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self, output_path: str):
        """Generate HTML report and save to file."""
        html = self._generate_html()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def _generate_html(self) -> str:
        """Generate complete HTML document."""
        # Calculate statistics
        total = len(self.results)
        only_human = len([r for r in self.results if r['has_human'] and not r['has_bot']])
        only_bot = len([r for r in self.results if r['has_bot'] and not r['has_human']])
        both = len([r for r in self.results if r['has_bot'] and r['has_human']])
        avg_score = sum(r['final_score'] for r in self.results) / total if total > 0 else 0

        clicked_count = sum(1 for h in self.human_report if h['human_clicked'] == 'YES')
        opened_count = sum(1 for h in self.human_report if h['human_opened'] == 'YES')

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.campaign_name} - GoCheck Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        .header {{
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}

        .header h1 {{
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            color: #666;
            font-size: 1.1em;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}

        .stat-card {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}

        .stat-card h3 {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}

        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}

        .stat-card .percentage {{
            font-size: 1.2em;
            color: #999;
        }}

        .stat-card.success .value {{ color: #10b981; }}
        .stat-card.warning .value {{ color: #f59e0b; }}
        .stat-card.danger .value {{ color: #ef4444; }}

        .chart-container {{
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }}

        .chart-container h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.5em;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}

        thead {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}

        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        }}

        th:hover {{
            background: rgba(255,255,255,0.1);
        }}

        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }}

        tr:hover {{
            background: #f9fafb;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}

        .badge.success {{
            background: #d1fae5;
            color: #065f46;
        }}

        .badge.warning {{
            background: #fef3c7;
            color: #92400e;
        }}

        .badge.danger {{
            background: #fee2e2;
            color: #991b1b;
        }}

        .badge.info {{
            background: #dbeafe;
            color: #1e40af;
        }}

        .filter-bar {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}

        .filter-bar input {{
            padding: 10px 15px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 1em;
            flex: 1;
            min-width: 250px;
        }}

        .filter-bar select {{
            padding: 10px 15px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 1em;
            background: white;
            cursor: pointer;
        }}

        .btn {{
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-size: 1em;
            cursor: pointer;
            transition: transform 0.2s;
        }}

        .btn:hover {{
            transform: scale(1.05);
        }}

        .score-bar {{
            width: 100%;
            height: 8px;
            background: #e5e7eb;
            border-radius: 4px;
            overflow: hidden;
        }}

        .score-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, #ef4444 0%, #f59e0b 50%, #10b981 100%);
            transition: width 0.3s ease;
        }}

        .details-row {{
            display: none;
            background: #f9fafb;
        }}

        .details-row td {{
            padding: 20px;
        }}

        .details-content {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            border-left: 4px solid #667eea;
        }}

        .ip-block {{
            background: #f3f4f6;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }}

        .ip-block h4 {{
            color: #667eea;
            margin-bottom: 10px;
        }}

        .event-list {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 10px;
        }}

        .event {{
            padding: 4px 10px;
            background: #dbeafe;
            color: #1e40af;
            border-radius: 6px;
            font-size: 0.85em;
        }}

        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: 1fr;
            }}

            .filter-bar {{
                flex-direction: column;
            }}

            .filter-bar input,
            .filter-bar select {{
                width: 100%;
            }}
        }}

        .footer {{
            text-align: center;
            color: white;
            padding: 20px;
            margin-top: 40px;
            font-size: 0.9em;
        }}

        .footer a {{
            color: white;
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ {self.campaign_name}</h1>
            <p class="subtitle">GoCheck Analysis Report - Generated on {self.timestamp}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Targets</h3>
                <div class="value">{total}</div>
            </div>
            <div class="stat-card success">
                <h3>Human Clicks</h3>
                <div class="value">{clicked_count}</div>
                <div class="percentage">({clicked_count/total*100:.1f}%)</div>
            </div>
            <div class="stat-card warning">
                <h3>Email Opens</h3>
                <div class="value">{opened_count}</div>
                <div class="percentage">({opened_count/total*100:.1f}%)</div>
            </div>
            <div class="stat-card">
                <h3>Real Users Only</h3>
                <div class="value">{only_human}</div>
                <div class="percentage">({only_human/total*100:.1f}%)</div>
            </div>
            <div class="stat-card danger">
                <h3>Bot/Scanner Only</h3>
                <div class="value">{only_bot}</div>
                <div class="percentage">({only_bot/total*100:.1f}%)</div>
            </div>
            <div class="stat-card warning">
                <h3>Mixed (Bot + Human)</h3>
                <div class="value">{both}</div>
                <div class="percentage">({both/total*100:.1f}%)</div>
            </div>
        </div>

        <div class="chart-container">
            <h2>📧 Email Analysis Results</h2>
            <div class="filter-bar">
                <input type="text" id="searchInput" placeholder="🔍 Search emails...">
                <select id="filterStatus">
                    <option value="all">All Results</option>
                    <option value="clicked">Clicked Only</option>
                    <option value="opened">Opened Only</option>
                    <option value="bot">Bot/Scanner Only</option>
                    <option value="human">Real User Only</option>
                </select>
                <button class="btn" onclick="resetFilters()">Reset</button>
            </div>

            <table id="resultsTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">Email ↕</th>
                        <th onclick="sortTable(1)">Opened ↕</th>
                        <th onclick="sortTable(2)">Clicked ↕</th>
                        <th onclick="sortTable(3)">Score ↕</th>
                        <th onclick="sortTable(4)">Classification ↕</th>
                        <th onclick="sortTable(5)">IPs ↕</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody id="resultsBody">
{self._generate_table_rows()}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated with <strong>GoCheck v2.2.0</strong> by <a href="https://github.com/Givaa/GoCheck" target="_blank">@Givaa</a>
        </div>
    </div>

    <script>
        // Search functionality
        document.getElementById('searchInput').addEventListener('keyup', function() {{
            const searchValue = this.value.toLowerCase();
            const rows = document.querySelectorAll('#resultsBody tr:not(.details-row)');

            rows.forEach(row => {{
                const email = row.cells[0].textContent.toLowerCase();
                row.style.display = email.includes(searchValue) ? '' : 'none';
                // Hide details row if parent is hidden
                const detailsRow = row.nextElementSibling;
                if (detailsRow && detailsRow.classList.contains('details-row')) {{
                    detailsRow.style.display = 'none';
                }}
            }});
        }});

        // Filter functionality
        document.getElementById('filterStatus').addEventListener('change', function() {{
            const filterValue = this.value;
            const rows = document.querySelectorAll('#resultsBody tr:not(.details-row)');

            rows.forEach(row => {{
                const opened = row.cells[1].textContent;
                const clicked = row.cells[2].textContent;
                const classification = row.cells[4].textContent.toLowerCase();

                let show = true;

                if (filterValue === 'clicked') {{
                    show = clicked === 'YES';
                }} else if (filterValue === 'opened') {{
                    show = opened === 'YES';
                }} else if (filterValue === 'bot') {{
                    show = classification.includes('bot') || classification.includes('scanner');
                }} else if (filterValue === 'human') {{
                    show = classification.includes('real user only');
                }}

                row.style.display = show ? '' : 'none';
                // Hide details row if parent is hidden
                const detailsRow = row.nextElementSibling;
                if (detailsRow && detailsRow.classList.contains('details-row')) {{
                    detailsRow.style.display = 'none';
                }}
            }});
        }});

        function resetFilters() {{
            document.getElementById('searchInput').value = '';
            document.getElementById('filterStatus').value = 'all';
            const rows = document.querySelectorAll('#resultsBody tr:not(.details-row)');
            rows.forEach(row => row.style.display = '');
            const detailsRows = document.querySelectorAll('.details-row');
            detailsRows.forEach(row => row.style.display = 'none');
        }}

        // Sort table
        function sortTable(columnIndex) {{
            const table = document.getElementById('resultsTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr:not(.details-row)'));

            rows.sort((a, b) => {{
                let aValue = a.cells[columnIndex].textContent.trim();
                let bValue = b.cells[columnIndex].textContent.trim();

                // Handle numeric values
                if (columnIndex === 3 || columnIndex === 5) {{
                    aValue = parseFloat(aValue) || 0;
                    bValue = parseFloat(bValue) || 0;
                }}

                if (aValue < bValue) return -1;
                if (aValue > bValue) return 1;
                return 0;
            }});

            // Re-append sorted rows
            rows.forEach(row => {{
                const detailsRow = row.nextElementSibling;
                tbody.appendChild(row);
                if (detailsRow && detailsRow.classList.contains('details-row')) {{
                    tbody.appendChild(detailsRow);
                }}
            }});
        }}

        // Toggle details
        function toggleDetails(email) {{
            const detailsRow = document.getElementById('details-' + email);
            const currentDisplay = detailsRow.style.display;
            detailsRow.style.display = currentDisplay === 'table-row' ? 'none' : 'table-row';
        }}
    </script>
</body>
</html>'''
        return html

    def _generate_table_rows(self) -> str:
        """Generate table rows for all results."""
        rows = []

        for result in self.results:
            email = result['email']
            email_safe = email.replace('@', '_at_').replace('.', '_')

            # Find human report entry for this email
            human_entry = next((h for h in self.human_report if h['email'] == email), None)

            opened = human_entry['human_opened'] if human_entry else 'NO'
            clicked = human_entry['human_clicked'] if human_entry else 'NO'
            score = result['final_score']
            classification = result['final_classification']
            num_ips = result['num_ips']

            # Determine badge class
            if classification == 'Real user only':
                badge_class = 'success'
            elif classification == 'Bot/scanner only':
                badge_class = 'danger'
            else:
                badge_class = 'warning'

            # Determine score color
            if score >= 70:
                score_color = '#10b981'
            elif score >= 40:
                score_color = '#f59e0b'
            else:
                score_color = '#ef4444'

            rows.append(f'''
                    <tr>
                        <td>{email}</td>
                        <td><span class="badge {'success' if opened == 'YES' else 'danger'}">{opened}</span></td>
                        <td><span class="badge {'success' if clicked == 'YES' else 'danger'}">{clicked}</span></td>
                        <td>
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <strong style="color: {score_color};">{score}</strong>
                                <div class="score-bar" style="flex: 1;">
                                    <div class="score-bar-fill" style="width: {score}%; background: {score_color};"></div>
                                </div>
                            </div>
                        </td>
                        <td><span class="badge {badge_class}">{classification}</span></td>
                        <td>{num_ips}</td>
                        <td><button class="btn" onclick="toggleDetails('{email_safe}')">View Details</button></td>
                    </tr>
                    <tr id="details-{email_safe}" class="details-row">
                        <td colspan="7">
                            <div class="details-content">
                                <h3>Detailed Analysis for {email}</h3>
{self._generate_ip_details(result)}
                            </div>
                        </td>
                    </tr>''')

        return '\n'.join(rows)

    def _generate_ip_details(self, result: Dict) -> str:
        """Generate IP analysis details for a result."""
        details = []

        for i, ip_analysis in enumerate(result['ip_analyses'], 1):
            ip = ip_analysis['ip']
            score = ip_analysis['score']
            classification = ip_analysis['classification']
            ip_type = ip_analysis['type']
            is_bot = ip_analysis['is_bot']
            events = ip_analysis['events']
            ip_details = ip_analysis.get('details', [])
            breakdown = ip_analysis.get('decision_breakdown', {})

            bot_badge = '<span class="badge danger">BOT</span>' if is_bot else '<span class="badge success">HUMAN</span>'

            # Generate decision breakdown HTML
            breakdown_html = self._generate_breakdown_html(breakdown) if breakdown else ''

            details.append(f'''
                                <div class="ip-block">
                                    <h4>IP #{i}: {ip} {bot_badge}</h4>
                                    <p><strong>Classification:</strong> {classification}</p>
                                    <p><strong>Type:</strong> {ip_type}</p>
                                    <p><strong>Score:</strong> {score}/100</p>
                                    <p><strong>Events:</strong></p>
                                    <div class="event-list">
{''.join(f'<span class="event">{event}</span>' for event in events)}
                                    </div>
                                    {f'<p style="margin-top: 10px;"><strong>Details:</strong></p><ul style="margin-left: 20px;">{"".join(f"<li>{detail}</li>" for detail in ip_details)}</ul>' if ip_details else ''}
                                    {breakdown_html}
                                </div>''')

        return '\n'.join(details)

    def _generate_breakdown_html(self, breakdown: Dict) -> str:
        """Generate HTML for decision breakdown."""
        if not breakdown:
            return ''

        steps_html = []
        for step in breakdown.get('steps', []):
            status_class = {'success': 'success', 'warning': 'warning', 'failed': 'danger'}.get(step.get('status', 'info'), 'info')

            details_html = ''
            if isinstance(step.get('details'), list):
                details_html = '<ul style="margin-left: 20px; margin-top: 5px;">' + ''.join(f'<li>{d}</li>' for d in step['details']) + '</ul>'
            elif step.get('details'):
                details_html = f'<p style="margin-left: 20px; margin-top: 5px;">{step["details"]}</p>'

            penalty_html = f'<span style="color: #ef4444; font-weight: bold;"> (-{step["penalty"]} points)</span>' if step.get('penalty', 0) > 0 else ''
            decision_html = f'<p style="margin-left: 20px; color: #ef4444; font-weight: bold;">{step["decision"]}</p>' if step.get('decision') else ''

            bonuses_html = ''
            if step.get('bonuses'):
                bonuses_html = '<ul style="margin-left: 20px; margin-top: 5px;">'
                for bonus in step['bonuses']:
                    bonuses_html += f'<li>{bonus["action"]}: <span style="color: #10b981; font-weight: bold;">+{bonus["points"]} points</span></li>'
                bonuses_html += '</ul>'

            steps_html.append(f'''
                <div style="padding: 10px; margin: 5px 0; background: #f9fafb; border-left: 3px solid {'#10b981' if status_class == 'success' else '#f59e0b' if status_class == 'warning' else '#ef4444'}; border-radius: 4px;">
                    <strong>{step['icon']} {step['name']}</strong>{penalty_html}
                    {details_html}
                    {bonuses_html}
                    {decision_html}
                </div>
            ''')

        # Score calculation
        calc = breakdown.get('score_calculation', {})
        calc_html = f'''
            <div style="background: #f3f4f6; padding: 15px; border-radius: 8px; margin-top: 10px;">
                <strong>📊 Score Calculation:</strong>
                <table style="width: 100%; margin-top: 10px; font-size: 0.9em;">
                    <tr><td>Base Score:</td><td style="text-align: right;">{calc.get('base_score', 100)}</td></tr>
                    <tr><td>IP Penalty:</td><td style="text-align: right; color: #ef4444;">{calc.get('ip_penalty', 0)}</td></tr>
                    <tr><td>Timing Penalty:</td><td style="text-align: right; color: #ef4444;">{calc.get('timing_penalty', 0)}</td></tr>
                    <tr><td>User Agent Penalty:</td><td style="text-align: right; color: #ef4444;">{calc.get('user_agent_penalty', 0)}</td></tr>
                    <tr><td>Bonuses:</td><td style="text-align: right; color: #10b981;">+{calc.get('bonuses', 0)}</td></tr>
                    <tr style="border-top: 2px solid #d1d5db;"><td><strong>Raw Total:</strong></td><td style="text-align: right;"><strong>{calc.get('raw_total', 0)}</strong></td></tr>
                    <tr><td><strong>Final Score (capped):</strong></td><td style="text-align: right;"><strong>{calc.get('capped_score', 0)}/100</strong></td></tr>
                </table>
            </div>
        '''

        # Final verdict
        verdict = breakdown.get('final_verdict', {})
        verdict_html = ''
        if verdict:
            verdict_color = '#10b981' if 'HUMAN' in verdict.get('classification', '') else '#ef4444'
            reasons_html = '<ul style="margin-left: 20px; margin-top: 5px;">' + ''.join(f'<li>{r}</li>' for r in verdict.get('reasons', [])) + '</ul>'

            verdict_html = f'''
                <div style="background: linear-gradient(135deg, {verdict_color}15 0%, {verdict_color}25 100%); padding: 15px; border-radius: 8px; margin-top: 10px; border: 2px solid {verdict_color};">
                    <h4 style="color: {verdict_color}; margin: 0 0 10px 0;">{verdict['icon']} Final Verdict: {verdict['classification']}</h4>
                    <p><strong>Why this decision was made:</strong></p>
                    {reasons_html}
                    <p style="margin-top: 10px; font-style: italic; color: #666;">{verdict.get('conclusion', '')}</p>
                </div>
            '''

        return f'''
            <details style="margin-top: 15px; background: white; border: 2px solid #e5e7eb; border-radius: 8px; padding: 15px;">
                <summary style="cursor: pointer; font-weight: bold; color: #667eea; user-select: none;">
                    🔍 Click to see Decision Breakdown (Why this classification?)
                </summary>
                <div style="margin-top: 15px;">
                    <h4 style="color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 5px;">Analysis Steps:</h4>
                    {''.join(steps_html)}
                    {calc_html}
                    {verdict_html}
                </div>
            </details>
        '''


class JSONReportGenerator:
    """Generate machine-readable JSON report."""

    def __init__(self, results: List[Dict], human_report: List[Dict], campaign_name: str = "GoPhish Campaign"):
        self.results = results
        self.human_report = human_report
        self.campaign_name = campaign_name
        self.timestamp = datetime.now().isoformat()

    def generate(self, output_path: str):
        """Generate JSON report and save to file."""
        report = {
            "campaign_name": self.campaign_name,
            "generated_at": self.timestamp,
            "generator": "GoCheck v2.2.0",
            "statistics": self._generate_statistics(),
            "results": self._serialize_results(),
            "human_report": self.human_report
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

    def _generate_statistics(self) -> Dict:
        """Generate campaign statistics."""
        total = len(self.results)
        only_human = len([r for r in self.results if r['has_human'] and not r['has_bot']])
        only_bot = len([r for r in self.results if r['has_bot'] and not r['has_human']])
        both = len([r for r in self.results if r['has_bot'] and r['has_human']])
        avg_score = sum(r['final_score'] for r in self.results) / total if total > 0 else 0

        clicked_count = sum(1 for h in self.human_report if h['human_clicked'] == 'YES')
        opened_count = sum(1 for h in self.human_report if h['human_opened'] == 'YES')

        return {
            "total_targets": total,
            "real_users_only": only_human,
            "bots_only": only_bot,
            "mixed": both,
            "average_score": round(avg_score, 2),
            "human_interactions": {
                "opened": opened_count,
                "opened_percentage": round(opened_count/total*100, 2) if total > 0 else 0,
                "clicked": clicked_count,
                "clicked_percentage": round(clicked_count/total*100, 2) if total > 0 else 0
            }
        }

    def _serialize_results(self) -> List[Dict]:
        """Serialize results to JSON-compatible format."""
        return [
            {
                **result,
                'ip_analyses': [
                    {
                        **ip_analysis,
                        'first_event': ip_analysis['first_event'].isoformat() if 'first_event' in ip_analysis else None,
                        'last_event': ip_analysis['last_event'].isoformat() if 'last_event' in ip_analysis else None
                    }
                    for ip_analysis in result['ip_analyses']
                ]
            }
            for result in self.results
        ]


class MarkdownReportGenerator:
    """Generate human-friendly Markdown report."""

    def __init__(self, results: List[Dict], human_report: List[Dict], campaign_name: str = "GoPhish Campaign"):
        self.results = results
        self.human_report = human_report
        self.campaign_name = campaign_name
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self, output_path: str):
        """Generate Markdown report and save to file."""
        md = self._generate_markdown()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)

    def _generate_markdown(self) -> str:
        """Generate complete Markdown document."""
        # Calculate statistics
        total = len(self.results)
        only_human = len([r for r in self.results if r['has_human'] and not r['has_bot']])
        only_bot = len([r for r in self.results if r['has_bot'] and not r['has_human']])
        both = len([r for r in self.results if r['has_bot'] and r['has_human']])
        avg_score = sum(r['final_score'] for r in self.results) / total if total > 0 else 0

        clicked_count = sum(1 for h in self.human_report if h['human_clicked'] == 'YES')
        opened_count = sum(1 for h in self.human_report if h['human_opened'] == 'YES')

        md = f'''# 🛡️ {self.campaign_name}

**GoCheck Analysis Report**
Generated on {self.timestamp}

---

## 📊 Executive Summary

| Metric | Value | Percentage |
|--------|-------|------------|
| **Total Targets** | {total} | 100% |
| **Human Clicks** | {clicked_count} | {clicked_count/total*100:.1f}% |
| **Email Opens** | {opened_count} | {opened_count/total*100:.1f}% |
| **Real Users Only** | {only_human} | {only_human/total*100:.1f}% |
| **Bot/Scanner Only** | {only_bot} | {only_bot/total*100:.1f}% |
| **Mixed (Bot + Human)** | {both} | {both/total*100:.1f}% |
| **Average Score** | {avg_score:.1f}/100 | - |

---

## ✅ Users Who Clicked the Link

{self._generate_clicked_users()}

---

## 📧 Detailed Email Analysis

{self._generate_detailed_analysis()}

---

## 📝 Recommendations

Based on the analysis results:

1. **High-Risk Users**: {clicked_count} users clicked the malicious link and should receive additional security awareness training
2. **Medium-Risk Users**: {opened_count - clicked_count} users opened the email but didn't click - consider targeted education
3. **Low-Risk Users**: {total - opened_count} users didn't interact with the email
4. **Bot Detection**: {only_bot + both} email addresses showed automated scanner activity

---

*Report generated with GoCheck v2.2.0 by @Givaa*
'''
        return md

    def _generate_clicked_users(self) -> str:
        """Generate list of users who clicked."""
        clicked_users = [h for h in self.human_report if h['human_clicked'] == 'YES']

        if not clicked_users:
            return "*No users clicked the link.*"

        lines = []
        for user in clicked_users:
            score = user['human_score']
            score_indicator = '🟢' if score >= 70 else '🟡' if score >= 40 else '🔴'
            lines.append(f"- {score_indicator} **{user['email']}** (Score: {score}/100, IP: {user['human_ip']})")

        return '\n'.join(lines)

    def _generate_detailed_analysis(self) -> str:
        """Generate detailed analysis for each email."""
        lines = []

        for result in self.results:
            email = result['email']
            score = result['final_score']
            classification = result['final_classification']
            num_ips = result['num_ips']

            # Determine emoji based on classification
            if classification == 'Real user only':
                emoji = '✅'
            elif classification == 'Bot/scanner only':
                emoji = '🤖'
            else:
                emoji = '⚠️'

            lines.append(f'''### {emoji} {email}

**Score**: {score}/100
**Classification**: {classification}
**Unique IPs**: {num_ips}

<details>
<summary>IP Analysis Details</summary>

{self._generate_ip_markdown(result)}

</details>
''')

        return '\n'.join(lines)

    def _generate_ip_markdown(self, result: Dict) -> str:
        """Generate IP analysis details in Markdown."""
        lines = []

        for i, ip_analysis in enumerate(result['ip_analyses'], 1):
            ip = ip_analysis['ip']
            score = ip_analysis['score']
            classification = ip_analysis['classification']
            ip_type = ip_analysis['type']
            is_bot = ip_analysis['is_bot']
            events = ip_analysis['events']
            details = ip_analysis.get('details', [])
            breakdown = ip_analysis.get('decision_breakdown', {})

            bot_indicator = '🤖 **BOT**' if is_bot else '👤 **HUMAN**'

            # Generate breakdown markdown
            breakdown_md = self._generate_breakdown_markdown(breakdown) if breakdown else ''

            lines.append(f'''#### IP #{i}: {ip} {bot_indicator}

- **Classification**: {classification}
- **Type**: {ip_type}
- **Score**: {score}/100
- **Events**: {', '.join(events)}
{f"- **Details**:\\n  " + "\\n  ".join(f"- {detail}" for detail in details) if details else ""}

{breakdown_md}
''')

        return '\n'.join(lines)

    def _generate_breakdown_markdown(self, breakdown: Dict) -> str:
        """Generate decision breakdown in Markdown format."""
        if not breakdown:
            return ''

        lines = ['<details>', '<summary><strong>🔍 Decision Breakdown - Why this classification?</strong></summary>', '']

        # Steps
        lines.append('**Analysis Steps:**')
        lines.append('')
        for step in breakdown.get('steps', []):
            penalty_str = f" **(-{step['penalty']} points)**" if step.get('penalty', 0) > 0 else ''
            lines.append(f"**{step['icon']} {step['name']}**{penalty_str}")

            if isinstance(step.get('details'), list):
                for detail in step['details']:
                    lines.append(f"  - {detail}")
            elif step.get('details'):
                lines.append(f"  {step['details']}")

            if step.get('bonuses'):
                for bonus in step['bonuses']:
                    lines.append(f"  - ✨ {bonus['action']}: **+{bonus['points']} points**")

            if step.get('decision'):
                lines.append(f"  > ⚠️ {step['decision']}")

            lines.append('')

        # Score calculation
        calc = breakdown.get('score_calculation', {})
        if calc:
            lines.append('**📊 Score Calculation:**')
            lines.append('')
            lines.append('| Component | Points |')
            lines.append('|-----------|--------|')
            lines.append(f"| Base Score | {calc.get('base_score', 100)} |")
            lines.append(f"| IP Penalty | {calc.get('ip_penalty', 0)} |")
            lines.append(f"| Timing Penalty | {calc.get('timing_penalty', 0)} |")
            lines.append(f"| User Agent Penalty | {calc.get('user_agent_penalty', 0)} |")
            lines.append(f"| Bonuses | +{calc.get('bonuses', 0)} |")
            lines.append(f"| **Raw Total** | **{calc.get('raw_total', 0)}** |")
            lines.append(f"| **Final Score (capped)** | **{calc.get('capped_score', 0)}/100** |")
            lines.append('')

        # Final verdict
        verdict = breakdown.get('final_verdict', {})
        if verdict:
            lines.append(f"**{verdict['icon']} Final Verdict: {verdict['classification']}**")
            lines.append('')
            lines.append('**Why this decision was made:**')
            for reason in verdict.get('reasons', []):
                lines.append(f"- {reason}")
            lines.append('')
            lines.append(f"*{verdict.get('conclusion', '')}*")

        lines.append('</details>')

        return '\n'.join(lines)
