# reports/dashboard_renderer.py

from jinja2 import Template

DASHBOARD_TEMPLATE = """
<div class="container mt-4">

    <h2 class="fw-bold text-primary mb-4">Hexora Enterprise SAST – Dashboard Overview</h2>

    <div class="row g-4">

        {% for sev, count in sev_counts.items() %}
        <div class="col-md-3">
            <div class="p-4 shadow-sm rounded text-white"
                 style="background: {{sev_colors[sev]}};">
                <h5 class="mb-1 text-capitalize">{{sev}}</h5>
                <h2 class="fw-bold">{{count}}</h2>
            </div>
        </div>
        {% endfor %}

    </div>

    <div class="mt-5 p-4 bg-white shadow-sm rounded">
        <h4 class="fw-bold text-primary">Executive Summary</h4>
        <p class="mt-2">
            A total of <b>{{total}}</b> findings were detected across all scanned files.
            Critical & High vulnerabilities should be remediated immediately.
        </p>
    </div>

</div>
"""

class DashboardRenderer:
    @staticmethod
    def render(findings):

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "medium")
            sev_counts[sev] += 1

        sev_colors = {
            "critical": "#d62828",
            "high": "#f77f00",
            "medium": "#fcbf49",
            "low": "#1d4ed8"
        }

        tpl = Template(DASHBOARD_TEMPLATE)
        return tpl.render(
            total=len(findings),
            sev_counts=sev_counts,
            sev_colors=sev_colors
        )