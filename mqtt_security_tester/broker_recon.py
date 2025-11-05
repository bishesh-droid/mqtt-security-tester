import socket
import ssl
import logging
from typing import Dict, Any, Optional

from mqtt_security_tester.config import Config

# Configure logging for this module
logger = logging.getLogger(__name__)

class BrokerRecon:
    """
    Performs reconnaissance on an MQTT broker to gather information such as
    version, TLS/SSL configuration, and open ports.
    """

    def __init__(self, config: Config):
        """
        Initializes the BrokerRecon with the application configuration.

        Args:
            config (Config): The application configuration object.
        """
        self.config = config
        self.host = self.config.get("broker.host")
        self.port = self.config.get("broker.port")
        self.timeout = self.config.get("broker.timeout")
        logger.info(f"BrokerRecon initialized for {self.host}:{self.port}")

    def check_port_open(self, port: int) -> bool:
        """
        Checks if a specific TCP port is open on the target host.

        Args:
            port (int): The port number to check.

        Returns:
            bool: True if the port is open, False otherwise.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.host, port))
                if result == 0:
                    logger.debug(f"Port {port} is open on {self.host}.")
                    return True
                else:
                    logger.debug(f"Port {port} is closed on {self.host}. Error: {result}")
                    return False
        except socket.error as e:
            logger.debug(f"Socket error while checking port {port}: {e}")
            return False

    def get_tls_info(self) -> Dict[str, Any]:
        """
        Attempts to establish a TLS connection and retrieve certificate information.

        Returns:
            Dict[str, Any]: A dictionary containing TLS certificate details, or an error message.
        """
        tls_info = {"tls_enabled": False, "error": None, "certificate_details": {}}
        if not self.config.get("broker.use_tls"):
            tls_info["error"] = "TLS not configured in settings.toml for broker."
            return tls_info

        try:
            # Check if the TLS port is open first
            if not self.check_port_open(self.port):
                tls_info["error"] = f"TLS port {self.port} is not open."
                return tls_info

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))

            context = ssl.create_default_context(cafile=self.config.get("broker.ca_certs") or None)
            # Allow insecure connections for testing if no CA is provided
            if not self.config.get("broker.ca_certs"):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                logger.warning("TLS check: No CA certs provided, disabling hostname verification and certificate validation.")

            # Load client certificate and key if provided
            client_cert = self.config.get("broker.client_cert")
            client_key = self.config.get("broker.client_key")
            if client_cert and client_key:
                context.load_cert_chain(client_cert, client_key)
                logger.debug("TLS check: Loaded client certificate and key.")

            with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                tls_info["tls_enabled"] = True
                cert = ssock.getpeercert()
                if cert:
                    tls_info["certificate_details"] = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert.get('version'),
                        "serialNumber": cert.get('serialNumber'),
                        "notBefore": cert.get('notBefore'),
                        "notAfter": cert.get('notAfter'),
                        "fingerprint_sha256": ssock.getpeercert(binary_form=True).hex() # Raw cert for fingerprint
                    }
                    # Check expiration
                    not_after_str = tls_info["certificate_details"].get("notAfter")
                    if not_after_str:
                        # Example format: 'Nov 15 12:00:00 2024 GMT'
                        # Need to parse this into a datetime object
                        try:
                            # Python's ssl module returns time in a specific format
                            not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            if datetime.now() > not_after_dt:
                                tls_info["certificate_details"]["expired"] = True
                                logger.warning("TLS check: Certificate is expired!")
                            else:
                                tls_info["certificate_details"]["expired"] = False
                                logger.info("TLS check: Certificate is valid.")
                        except ValueError:
                            logger.warning(f"Could not parse certificate expiration date: {not_after_str}")

                logger.info("Successfully retrieved TLS certificate details.")

        except ssl.SSLError as e:
            tls_info["error"] = f"SSL/TLS error: {e}"
            logger.error(f"SSL/TLS error during reconnaissance: {e}")
        except socket.timeout:
            tls_info["error"] = "Connection timed out during TLS handshake."
            logger.error("Connection timed out during TLS handshake.")
        except ConnectionRefusedError:
            tls_info["error"] = "Connection refused during TLS handshake."
            logger.error("Connection refused during TLS handshake.")
        except Exception as e:
            tls_info["error"] = f"An unexpected error occurred during TLS check: {e}"
            logger.error(f"Unexpected error during TLS check: {e}")
        finally:
            if 'sock' in locals() and sock.fileno() != -1:
                sock.close()
        return tls_info

    def get_broker_version(self) -> Optional[str]:
        """
        Attempts to fingerprint the MQTT broker version.
        This is often difficult without specific protocol interactions or banner grabbing.
        For now, this is a placeholder and might require more advanced techniques
        or specific knowledge of broker responses.

        Returns:
            Optional[str]: The broker version string if found, otherwise None.
        """
        # MQTT protocol does not typically expose version information directly in a banner.
        # More advanced fingerprinting would involve analyzing specific protocol behaviors
        # or known vulnerabilities for different broker versions.
        logger.info("Broker version fingerprinting is an advanced feature and not fully implemented here.")
        return None

# Example Usage (for direct testing/demonstration)
if __name__ == "__main__":
    import sys
    import os
    from datetime import datetime

    # Setup basic logging for example
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Ensure config is loaded (adjust path if needed for direct run)
    try:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config', 'settings.toml')
        app_config = Config(config_path=config_path)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n--- Broker Reconnaissance Demonstration ---")

    recon = BrokerRecon(app_config)

    # Test port open
    print(f"\nChecking if port {app_config.get('broker.port')} is open...")
    if recon.check_port_open(app_config.get('broker.port')):
        print(f"Port {app_config.get('broker.port')} is open.")
    else:
        print(f"Port {app_config.get('broker.port')} is closed or unreachable.")

    # Test TLS info
    print("\nChecking TLS information...")
    tls_details = recon.get_tls_info()
    if tls_details["tls_enabled"]:
        print("TLS is enabled and certificate details retrieved:")
        for key, value in tls_details["certificate_details"].items():
            print(f"  {key}: {value}")
    elif tls_details["error"]:
        print(f"TLS check failed: {tls_details['error']}")
    else:
        print("TLS is not enabled or configured for testing.")

    # Test broker version (placeholder)
    print("\nAttempting to get broker version...")
    version = recon.get_broker_version()
    if version:
        print(f"Broker Version: {version}")
    else:
        print("Could not determine broker version (feature not fully implemented or not exposed).")
