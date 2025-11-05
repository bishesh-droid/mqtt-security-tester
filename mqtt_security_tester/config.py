import toml
import os
import logging

# Set up basic logging for the config module
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Config:
    """
    Handles loading and providing access to application configuration.
    Configuration is loaded from a TOML file.
    """
    _instance = None
    _config_data = None
    _config_path = None

    def __new__(cls, config_path=None):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._config_path = config_path if config_path else os.path.join(
                os.path.dirname(os.path.abspath(__file__)), '..', 'config', 'settings.toml'
            )
            cls._load_config()
        return cls._instance

    @classmethod
    def _load_config(cls):
        """
        Loads the configuration from the TOML file.
        """
        if not os.path.exists(cls._config_path):
            logging.error(f"Configuration file not found: {cls._config_path}")
            raise FileNotFoundError(f"Configuration file not found: {cls._config_path}")

        try:
            with open(cls._config_path, 'r') as f:
                cls._config_data = toml.load(f)
            logging.info(f"Configuration loaded from {cls._config_path}")
            cls._validate_config()
        except toml.TomlDecodeError as e:
            logging.error(f"Error decoding TOML configuration: {e}")
            raise ValueError(f"Invalid TOML configuration: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while loading configuration: {e}")
            raise

    @classmethod
    def _validate_config(cls):
        """
        Validates the loaded configuration to ensure all required keys are present
        and values are of the correct type.
        """
        required_sections = ["broker", "credentials", "topics", "scan_options"]
        for section in required_sections:
            if section not in cls._config_data:
                raise ValueError(f"Missing required section in config: [{section}]")

        # Validate [broker] section
        broker_config = cls._config_data["broker"]
        if not isinstance(broker_config.get("host"), str) or not broker_config.get("host"):
            raise ValueError("Config error: 'broker.host' must be a non-empty string.")
        if not isinstance(broker_config.get("port"), int) or not (1 <= broker_config["port"] <= 65535):
            raise ValueError("Config error: 'broker.port' must be an integer between 1 and 65535.")
        if not isinstance(broker_config.get("use_tls"), bool):
            raise ValueError("Config error: 'broker.use_tls' must be a boolean.")
        if not isinstance(broker_config.get("ca_certs"), str):
            raise ValueError("Config error: 'broker.ca_certs' must be a string.")
        if not isinstance(broker_config.get("client_cert"), str):
            raise ValueError("Config error: 'broker.client_cert' must be a string.")
        if not isinstance(broker_config.get("client_key"), str):
            raise ValueError("Config error: 'broker.client_key' must be a string.")
        if not isinstance(broker_config.get("protocol_version"), str) or broker_config["protocol_version"] not in ["3.1", "3.1.1", "5"]:
            raise ValueError("Config error: 'broker.protocol_version' must be '3.1', '3.1.1', or '5'.")
        if not isinstance(broker_config.get("timeout"), (int, float)) or broker_config["timeout"] <= 0:
            raise ValueError("Config error: 'broker.timeout' must be a positive number.")

        # Validate [credentials] section
        creds_config = cls._config_data["credentials"]
        if not isinstance(creds_config.get("username"), str):
            raise ValueError("Config error: 'credentials.username' must be a string.")
        if not isinstance(creds_config.get("password"), str):
            raise ValueError("Config error: 'credentials.password' must be a string.")
        if not isinstance(creds_config.get("weak_usernames"), list) or not all(isinstance(u, str) for u in creds_config["weak_usernames"]):
            raise ValueError("Config error: 'credentials.weak_usernames' must be a list of strings.")
        if not isinstance(creds_config.get("weak_passwords"), list) or not all(isinstance(p, str) for p in creds_config["weak_passwords"]):
            raise ValueError("Config error: 'credentials.weak_passwords' must be a list of strings.")

        # Validate [topics] section
        topics_config = cls._config_data["topics"]
        if not isinstance(topics_config.get("auth_test_topics"), list) or not all(isinstance(t, str) for t in topics_config["auth_test_topics"]):
            raise ValueError("Config error: 'topics.auth_test_topics' must be a list of strings.")
        if not isinstance(topics_config.get("publish_test_topic"), str) or not topics_config.get("publish_test_topic"):
            raise ValueError("Config error: 'topics.publish_test_topic' must be a non-empty string.")
        if not isinstance(topics_config.get("subscribe_test_topic"), str) or not topics_config.get("subscribe_test_topic"):
            raise ValueError("Config error: 'topics.subscribe_test_topic' must be a non-empty string.")
        if not isinstance(topics_config.get("retained_test_topic"), str) or not topics_config.get("retained_test_topic"):
            raise ValueError("Config error: 'topics.retained_test_topic' must be a non-empty string.")
        if not isinstance(topics_config.get("lwt_test_topic"), str) or not topics_config.get("lwt_test_topic"):
            raise ValueError("Config error: 'topics.lwt_test_topic' must be a non-empty string.")

        # Validate [scan_options] section
        scan_options_config = cls._config_data["scan_options"]
        for key in ["test_anonymous_access", "test_weak_credentials", "test_authorization_bypass",
                    "test_topic_enumeration", "test_retained_messages", "test_lwt", "test_tls_config"]:
            if not isinstance(scan_options_config.get(key), bool):
                raise ValueError(f"Config error: 'scan_options.{key}' must be a boolean.")
        if not isinstance(scan_options_config.get("report_output_dir"), str):
            raise ValueError("Config error: 'scan_options.report_output_dir' must be a string.")

        logging.info("Configuration validated successfully.")

    @classmethod
    def get(cls, key, default=None):
        """
        Retrieves a configuration value using a dot-separated key (e.g., "broker.host").
        """
        if cls._config_data is None:
            cls._load_config() # Ensure config is loaded if accessed directly without instantiation

        parts = key.split('.')
        current = cls._config_data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    @classmethod
    def reload(cls):
        """
        Reloads the configuration from the file.
        """
        cls._load_config()

# Example usage (for testing purposes, not part of the main application flow)
if __name__ == "__main__":
    try:
        # Instantiate Config (loads config if not already loaded)
        app_config = Config()

        # Accessing configuration values
        broker_host = app_config.get("broker.host")
        weak_users = app_config.get("credentials.weak_usernames")
        report_dir = app_config.get("scan_options.report_output_dir")

        print(f"Broker Host: {broker_host}")
        print(f"Weak Usernames: {weak_users}")
        print(f"Report Output Directory: {report_dir}")

        # Test with a non-existent key
        non_existent = app_config.get("non.existent.key", "default_value")
        print(f"Non-existent key: {non_existent}")

    except Exception as e:
        print(f"Configuration error: {e}")
