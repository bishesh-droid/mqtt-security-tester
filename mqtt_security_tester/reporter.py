import os
import json
from datetime import datetime
from typing import List, Dict, Any

from mqtt_security_tester.config import Config

class Reporter:
    """
    Generates reports from the security scan results.
    """

    def __init__(self, config: Config):
        """
        Initializes the Reporter with the application configuration.

        Args:
            config (Config): The application configuration object.
        """
        self.config = config
        self.report_output_dir = self.config.get("scan_options.report_output_dir")
        self._ensure_report_directory_exists()

    def _ensure_report_directory_exists(self):
        """
        Ensures that the report output directory exists.
        """
        if not os.path.exists(self.report_output_dir):
            os.makedirs(self.report_output_dir, exist_ok=True)

    def generate_text_report(self, scan_results: List[Dict[str, Any]], broker_info: Dict[str, Any]) -> str:
        """
        Generates a human-readable text report of the scan results.

        Args:
            scan_results (List[Dict[str, Any]]): A list of findings from the scanner.
            broker_info (Dict[str, Any]): Information gathered about the broker.

        Returns:
            str: The formatted text report.
        """
        report_lines = []
        report_lines.append("=" * 50)
        report_lines.append("MQTT Security Scan Report")
        report_lines.append("=" * 50)
        report_lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Target Broker: {self.config.get("broker.host")}:{self.config.get("broker.port")}")
        report_lines.append("\nBroker Information:")
        for key, value in broker_info.items():
            if isinstance(value, dict):
                report_lines.append(f"  {key.replace('_', ' ').title()}:")
                for sub_key, sub_value in value.items():
                    report_lines.append(f"    {sub_key.replace('_', ' ').title()}: {sub_value}")
            else:
                report_lines.append(f"  {key.replace('_', ' ').title()}: {value}")

        report_lines.append("\n" + "=" * 50)
        report_lines.append("Scan Findings")
        report_lines.append("=" * 50)

        if not scan_results:
            report_lines.append("No vulnerabilities or misconfigurations found.")
        else:
            # Sort findings by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_results = sorted(scan_results, key=lambda x: severity_order.get(x.get("severity", "INFO"), 99))

            for i, finding in enumerate(sorted_results):
                report_lines.append(f"\nFinding {i+1}:")
                report_lines.append(f"  Test Name: {finding.get("test_name", "N/A")}")
                report_lines.append(f"  Severity: {finding.get("severity", "N/A")}")
                report_lines.append(f"  Description: {finding.get("description", "N/A")}")
                details = finding.get("details")
                if details:
                    report_lines.append("  Details:")
                    for key, value in details.items():
                        report_lines.append(f"    {key}: {value}")

        report_lines.append("\n" + "=" * 50)
        report_lines.append("End of Report")
        report_lines.append("=" * 50)

        return "\n".join(report_lines)

    def save_report(self, report_content: str, format: str = "txt") -> str:
        """
        Saves the generated report to a file.

        Args:
            report_content (str): The content of the report.
            format (str): The format of the report (e.g., "txt", "json").

        Returns:
            str: The absolute path to the saved report file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mqtt_scan_report_{timestamp}.{format}"
        filepath = os.path.join(self.report_output_dir, filename)

        with open(filepath, 'w') as f:
            f.write(report_content)

        return os.path.abspath(filepath)

    def generate_json_report(self, scan_results: List[Dict[str, Any]], broker_info: Dict[str, Any]) -> str:
        """
        Generates a JSON report of the scan results.

        Args:
            scan_results (List[Dict[str, Any]]): A list of findings from the scanner.
            broker_info (Dict[str, Any]): Information gathered about the broker.

        Returns:
            str: The JSON formatted report string.
        """
        report_data = {
            "scan_date": datetime.now().isoformat(),
            "target_broker": {
                "host": self.config.get("broker.host"),
                "port": self.config.get("broker.port")
            },
            "broker_info": broker_info,
            "findings": scan_results
        }
        return json.dumps(report_data, indent=4)

# Example Usage (for direct testing/demonstration)
if __name__ == "__main__":
    import sys
    import os

    # Setup basic logging for example
    import logging
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Ensure config is loaded (adjust path if needed for direct run)
    try:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config', 'settings.toml')
        app_config = Config(config_path=config_path)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n--- Reporter Demonstration ---")

    reporter = Reporter(app_config)

    # Dummy scan results
    dummy_scan_results = [
        {
            "test_name": "Anonymous Access Test",
            "severity": "CRITICAL",
            "description": "Broker allows anonymous connections.",
            "details": {"host": "localhost", "port": 1883}
        },
        {
            "test_name": "Weak Credentials Test",
            "severity": "HIGH",
            "description": "Broker accepts weak credentials: admin:password",
            "details": {"host": "localhost", "port": 1883, "username": "admin", "password": "password"}
        },
        {
            "test_name": "TLS Configuration Check",
            "severity": "INFO",
            "description": "TLS is enabled, but certificate validation is disabled.",
            "details": {"host": "localhost", "port": 8883, "tls_enabled": True, "validation": "disabled"}
        }
    ]

    # Dummy broker info
    dummy_broker_info = {
        "port_1883_open": True,
        "port_8883_open": False,
        "tls_info": {
            "tls_enabled": False,
            "error": "TLS not configured in settings.toml for broker."
        },
        "broker_version": "Unknown"
    }

    # Generate and print text report
    text_report = reporter.generate_text_report(dummy_scan_results, dummy_broker_info)
    print("\n" + text_report)

    # Save text report
    saved_text_report_path = reporter.save_report(text_report, format="txt")
    print(f"Text report saved to: {saved_text_report_path}")

    # Generate and save JSON report
    json_report = reporter.generate_json_report(dummy_scan_results, dummy_broker_info)
    saved_json_report_path = reporter.save_report(json_report, format="json")
    print(f"JSON report saved to: {saved_json_report_path}")
