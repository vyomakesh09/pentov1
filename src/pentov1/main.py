import json
import os
from datetime import datetime
from crewai import Crew, Process
from pentov1.tasks import (
    create_recon_task,
    create_vuln_assessment_task,
    create_exploitation_task,
    create_reporting_task
)

def run_security_assessment(target_site: str):
    tasks = [
        create_recon_task(target_site),
        create_vuln_assessment_task(),
        create_exploitation_task(),
        create_reporting_task()
    ]

    crew = Crew(
        tasks=tasks,
        process=Process.sequential,
        verbose=2
    )
    results = crew.kickoff()
    process_results(target_site, results)
    return results

def process_results(target_site: str, results):
    results_dir = "security_assessment_results"
    os.makedirs(results_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_assessment_{timestamp}.json"
    file_path = os.path.join(results_dir, filename)

    formatted_results = {
        "target_site": target_site,
        "assessment_date": datetime.now().isoformat(),
        "findings": results
    }

    with open(file_path, 'w') as f:
        json.dump(formatted_results, f, indent=4, default=str)

    print(f"Security assessment results saved to: {file_path}")

def run():
    target_site = "https://example.com"
    results = run_security_assessment(target_site)
    print("Security assessment completed. Check the generated report for details.")

if __name__ == "__main__":
    run()
