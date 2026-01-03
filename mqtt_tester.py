import argparse
import sys
import logging
import os
from typing import List, Optional, Tuple

from mqtt_security_tester.config import Config
from mqtt_security_tester.mqtt_client_wrapper import MQTTClientWrapper
from mqtt_security_tester.broker_recon import BrokerRecon
from mqtt_security_tester.vulnerability_scanner import VulnerabilityScanner
from mqtt_security_tester.reporter import Reporter

def setup_logging(config: Config):
    """
    Sets up the logging configuration based on the settings in the Config object.
    """
    log_level_str = config.get("logging.level", "INFO").upper()
    log_file_name = config.get("logging.file", "mqtt_security_tester.log")

    # Map string log levels to logging module constants
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Construct absolute path for the log file
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    log_file_path = os.path.join(project_root, log_file_name)

    # Ensure log directory exists if log_file_name includes a path
    log_dir = os.path.dirname(log_file_path)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file_path),
            logging.StreamHandler(sys.stdout) # Also log to console
        ]
    )
    logging.info(f"Logging set up. Level: {log_level_str}, File: {log_file_path}")

def read_credentials_from_file(filepath: str) -> List[Tuple[str, str]]:
    """
    Reads username:password pairs from a file, one per line.
    """
    credentials = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    user, passwd = line.split(':', 1)
                    credentials.append((user, passwd))
                elif line:
                    logging.warning(f"Skipping malformed credential line: {line}")
    except FileNotFoundError:
        logging.error(f"Credential file not found: {filepath}")
    return credentials

def read_list_from_file(filepath: str) -> List[str]:
    """
    Reads a list of items (e.g., usernames, passwords) from a file, one per line.
    """
    items = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    items.append(line)
    except FileNotFoundError:
        logging.error(f"List file not found: {filepath}")
    return items

def main():
    """
    Main function to parse command-line arguments and execute the MQTT security tests.
    """
    # Load configuration first to set up logging correctly
    try:
        config = Config()
        # Override default logging file to be in the project root
        if "logging" not in config._config_data:
            config._config_data["logging"] = {}
        config._config_data["logging"]["file"] = "mqtt_security_tester.log"
        setup_logging(config)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        sys.exit(1)

    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(
        description="A comprehensive command-line MQTT security tester."
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scans against the MQTT broker.")
    scan_parser.add_argument(
        "--host", type=str, help="Override broker host from config."
    )
    scan_parser.add_argument(
        "--port", type=int, help="Override broker port from config."
    )
    scan_parser.add_argument(
        "--username", type=str, help="Override default username for tests."
    )
    scan_parser.add_argument(
        "--password", type=str, help="Override default password for tests."
    )
    scan_parser.add_argument(
        "--anon", action="store_true", help="Only run anonymous access test."
    )
    scan_parser.add_argument(
        "--weak-creds", action="store_true", help="Only run weak credentials test."
    )
    scan_parser.add_argument(
        "--custom-creds", type=str, help="Test with a specific username:password pair (e.g., user:pass)."
    )
    scan_parser.add_argument(
        "--custom-creds-file", type=str, help="Test with username:password pairs from a file (one per line)."
    )
    scan_parser.add_argument(
        "--bruteforce-users", type=str, help="File containing usernames for bruteforce (one per line)."
    )
    scan_parser.add_argument(
        "--bruteforce-passwords", type=str, help="File containing passwords for bruteforce (one per line)."
    )
    scan_parser.add_argument(
        "--authz", action="store_true", help="Only run authorization bypass test."
    )
    scan_parser.add_argument(
        "--topic-enum", action="store_true", help="Only run topic enumeration test."
    )
    scan_parser.add_argument(
        "--retained", action="store_true", help="Only run retained messages test."
    )
    scan_parser.add_argument(
        "--lwt", action="store_true", help="Only run Last Will and Testament (LWT) abuse test."
    )
    scan_parser.add_argument(
        "--tls", action="store_true", help="Only run TLS configuration check."
    )
    scan_parser.add_argument(
        "--report-format", type=str, choices=["txt", "json"], default="txt", help="Output report format."
    )

    # List tests command
    list_tests_parser = subparsers.add_parser("list-tests", help="List all available security tests.")

    args = parser.parse_args()

    if args.command == "scan":
        # Override config values if provided via CLI
        if 'host' in args and args.host: config._config_data["broker"]["host"] = args.host
        if 'port' in args and args.port: config._config_data["broker"]["port"] = args.port
        if 'username' in args and args.username: config._config_data["credentials"]["username"] = args.username
        if 'password' in args and args.password: config._config_data["credentials"]["password"] = args.password

        # Determine which tests to run based on CLI arguments
        run_all_tests = not any([
            'anon' in args and args.anon, 'weak_creds' in args and args.weak_creds,
            'custom_creds' in args and args.custom_creds, 'custom_creds_file' in args and args.custom_creds_file,
            'bruteforce_users' in args and args.bruteforce_users, 'bruteforce_passwords' in args and args.bruteforce_passwords,
            'authz' in args and args.authz, 'topic_enum' in args and args.topic_enum,
            'retained' in args and args.retained, 'lwt' in args and args.lwt, 'tls' in args and args.tls
        ])

        scanner = VulnerabilityScanner(config)
        recon = BrokerRecon(config)
        reporter = Reporter(config)

        broker_info = {
            "host": config.get("broker.host"),
            "port": config.get("broker.port"),
            "tls_enabled_in_config": config.get("broker.use_tls"),
            "port_open": recon.check_port_open(config.get("broker.port"))
        }
        logger.info(f"Starting MQTT security scan for {broker_info['host']}:{broker_info['port']}")

        # Run broker reconnaissance first
        if config.get("broker.use_tls") or ('tls' in args and args.tls) or run_all_tests:
            tls_info = recon.get_tls_info()
            broker_info["tls_info"] = tls_info
            if tls_info.get("error"):
                scanner._record_finding(
                    "TLS Configuration Check",
                    "ERROR",
                    f"TLS check encountered an error: {tls_info['error']}",
                    {"host": broker_info["host"], "port": broker_info["port"]}
                )
            elif tls_info.get("tls_enabled"):
                scanner._record_finding(
                    "TLS Configuration Check",
                    "INFO",
                    "TLS is enabled and certificate details retrieved.",
                    tls_info["certificate_details"]
                )
                if tls_info["certificate_details"].get("expired"):
                     scanner._record_finding(
                        "TLS Configuration Check",
                        "HIGH",
                        "TLS certificate is expired!",
                        tls_info["certificate_details"]
                    )
            else:
                scanner._record_finding(
                    "TLS Configuration Check",
                    "INFO",
                    "TLS is not enabled or configured for testing.",
                    {"host": broker_info["host"], "port": broker_info["port"]}
                )

        # Determine credentials to use for tests that require them
        test_username = args.username if 'username' in args and args.username is not None else config.get("credentials.username")
        test_password = args.password if 'password' in args and args.password is not None else config.get("credentials.password")

        if run_all_tests:
            scanner.run_all_scans(username=test_username, password=test_password)
        else:
            if 'anon' in args and args.anon: scanner.test_anonymous_access()
            if 'weak_creds' in args and args.weak_creds: scanner.test_weak_credentials()
            if 'custom_creds' in args and args.custom_creds:
                if ':' in args.custom_creds:
                    user, passwd = args.custom_creds.split(':', 1)
                    scanner.test_custom_credentials(user, passwd)
                else:
                    logger.error("Invalid format for --custom-creds. Use username:password.")
            if 'custom_creds_file' in args and args.custom_creds_file:
                creds_list = read_credentials_from_file(args.custom_creds_file)
                for user, passwd in creds_list:
                    scanner.test_custom_credentials(user, passwd)
            if 'bruteforce_users' in args and args.bruteforce_users and 'bruteforce_passwords' in args and args.bruteforce_passwords:
                user_list = read_list_from_file(args.bruteforce_users)
                pass_list = read_list_from_file(args.bruteforce_passwords)
                if user_list and pass_list:
                    scanner.test_bruteforce_credentials(user_list, pass_list)
            elif 'bruteforce_users' in args and args.bruteforce_users or 'bruteforce_passwords' in args and args.bruteforce_passwords:
                logger.error("Both --bruteforce-users and --bruteforce-passwords must be provided for bruteforce test.")

            if 'authz' in args and args.authz: scanner.test_authorization_bypass(username=test_username, password=test_password)
            if 'topic_enum' in args and args.topic_enum: scanner.test_topic_enumeration(username=test_username, password=test_password)
            if 'retained' in args and args.retained: scanner.test_retained_messages(username=test_username, password=test_password)
            if 'lwt' in args and args.lwt: scanner.test_lwt_abuse(username=test_username, password=test_password)
            # TLS check is handled above as part of recon

        # Generate and save report
        scan_results = scanner.get_results()
        if 'report_format' in args and args.report_format == "json":
            report_content = reporter.generate_json_report(scan_results, broker_info)
        else:
            report_content = reporter.generate_text_report(scan_results, broker_info)

        report_path = reporter.save_report(report_content, format=args.report_format)
        logger.info(f"Scan completed. Report saved to: {report_path}")
        print(f"\nScan completed. Report saved to: {report_path}")

    elif args.command == "list-tests":
        print("\nAvailable MQTT Security Tests:")
        print("  - Anonymous Access Test: Checks if the broker allows connections without credentials.")
        print("  - Weak Credentials Test: Tries common weak username/password combinations.")
        print("  - Custom Credentials Test: Tests a specific username:password pair or a list from a file.")
        print("  - Bruteforce Credentials Test: Attempts to bruteforce credentials from provided lists.")
        print("  - Authorization Bypass Test: Checks if clients can publish/subscribe to restricted topics.")
        print("  - Topic Enumeration Test: Checks if clients can discover topics using wildcard subscriptions.")
        print("  - Retained Messages Test: Looks for sensitive information in retained messages.")
        print("  - Last Will and Testament (LWT) Abuse Test: Checks for potential misuse of LWT messages.")
        print("  - TLS Configuration Check: Verifies TLS/SSL setup and certificate validity.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
