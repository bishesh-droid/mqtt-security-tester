import paho.mqtt.client as mqtt
import ssl
import time
import logging
from typing import Optional, Callable, Dict, Any

from mqtt_security_tester.config import Config

# Configure logging for this module
logger = logging.getLogger(__name__)

class MQTTClientWrapper:
    """
    A wrapper around paho.mqtt.client to simplify MQTT operations and manage connection state.
    Handles connection, disconnection, publishing, subscribing, and message reception.
    """

    def __init__(self, client_id: str, config: Config, clean_session: bool = True):
        """
        Initializes the MQTTClientWrapper.

        Args:
            client_id (str): The MQTT client ID to use.
            config (Config): The application configuration object.
            clean_session (bool): Set to True for a clean session (no persistent session).
        """
        self.client_id = client_id
        self.config = config
        self.clean_session = clean_session
        self.client = mqtt.Client(client_id=self.client_id, clean_session=self.clean_session, protocol=self._get_mqtt_protocol())
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        self.client.on_publish = self._on_publish
        self.client.on_subscribe = self._on_subscribe

        self.is_connected = False
        self.messages_received = []
        self.connect_rc = None # Result code of connection attempt

        self._setup_credentials()
        self._setup_tls()

        logger.info(f"MQTTClientWrapper initialized for client ID: {self.client_id}")

    def _get_mqtt_protocol(self) -> int:
        """
        Returns the paho.mqtt.client protocol constant based on config.
        """
        protocol_version = self.config.get("broker.protocol_version")
        if protocol_version == "3.1":
            return mqtt.MQTTv31
        elif protocol_version == "3.1.1":
            return mqtt.MQTTv311
        elif protocol_version == "5":
            return mqtt.MQTTv5
        else:
            logger.warning(f"Unknown MQTT protocol version: {protocol_version}. Defaulting to MQTTv311.")
            return mqtt.MQTTv311

    def _setup_credentials(self):
        """
        Sets up username and password for the MQTT client if provided in config.
        """
        username = self.config.get("credentials.username")
        password = self.config.get("credentials.password")
        if username or password:
            self.client.username_pw_set(username, password)
            logger.debug(f"MQTT client credentials set: username={username}")

    def _setup_tls(self):
        """
        Configures TLS/SSL for the MQTT client if enabled in config.
        """
        if self.config.get("broker.use_tls"):
            ca_certs = self.config.get("broker.ca_certs")
            client_cert = self.config.get("broker.client_cert")
            client_key = self.config.get("broker.client_key")

            try:
                if ca_certs and client_cert and client_key:
                    self.client.tls_set(ca_certs=ca_certs, certfile=client_cert, keyfile=client_key, tls_version=ssl.PROTOCOL_TLSv1_2)
                    logger.info("MQTT client TLS configured with CA, client cert, and key.")
                elif ca_certs:
                    self.client.tls_set(ca_certs=ca_certs, tls_version=ssl.PROTOCOL_TLSv1_2)
                    logger.info("MQTT client TLS configured with CA cert only.")
                else:
                    # No CA certs provided, but TLS is enabled. This might be for self-signed certs or testing.
                    # Use CERT_NONE for no certificate validation, or CERT_OPTIONAL for optional validation.
                    self.client.tls_set(tls_version=ssl.PROTOCOL_TLSv1_2)
                    self.client.tls_insecure_set(True) # Allow insecure server connections for testing
                    logger.warning("MQTT client TLS enabled without CA certs. Certificate validation is disabled.")
            except Exception as e:
                logger.error(f"Error setting up TLS for MQTT client: {e}")
                raise

    def _on_connect(self, client, userdata, flags, rc):
        """
        Callback function for when the client connects to the MQTT broker.
        """
        self.connect_rc = rc
        if rc == 0:
            self.is_connected = True
            logger.info(f"Client {self.client_id} connected successfully to MQTT broker.")
        else:
            self.is_connected = False
            logger.error(f"Client {self.client_id} failed to connect, return code {rc}: {mqtt.connack_string(rc)}")

    def _on_disconnect(self, client, userdata, rc):
        """
        Callback function for when the client disconnects from the MQTT broker.
        """
        self.is_connected = False
        logger.info(f"Client {self.client_id} disconnected with result code {rc}: {mqtt.error_string(rc)}")

    def _on_message(self, client, userdata, msg):
        """
        Callback function for when a message is received from the MQTT broker.
        """
        logger.debug(f"Message received on topic '{msg.topic}': {msg.payload.decode()}")
        self.messages_received.append({
            "topic": msg.topic,
            "payload": msg.payload.decode(),
            "qos": msg.qos,
            "retain": msg.retain,
            "timestamp": time.time()
        })

    def _on_publish(self, client, userdata, mid):
        """
        Callback function for when a message is published.
        """
        logger.debug(f"Message with mid {mid} published.")

    def _on_subscribe(self, client, userdata, mid, granted_qos):
        """
        Callback function for when a subscription is acknowledged by the broker.
        """
        logger.debug(f"Subscribed with mid {mid}, granted QoS: {granted_qos}")

    def connect(self, username: Optional[str] = None, password: Optional[str] = None) -> bool:
        """
        Connects the MQTT client to the broker.

        Args:
            username (Optional[str]): Username for connection. Overrides config if provided.
            password (Optional[str]): Password for connection. Overrides config if provided.

        Returns:
            bool: True if connection was successful, False otherwise.
        """
        host = self.config.get("broker.host")
        port = self.config.get("broker.port")
        timeout = self.config.get("broker.timeout")

        if username is not None or password is not None:
            self.client.username_pw_set(username, password)
            logger.debug(f"Overriding credentials for connection: username={username}")

        try:
            self.client.connect(host, port, int(timeout))
            self.client.loop_start() # Start a background thread for network traffic
            # Wait for connection to establish or fail
            start_time = time.time()
            while not self.is_connected and (time.time() - start_time < timeout + 1): # +1 for a small buffer
                if self.connect_rc is not None and self.connect_rc != 0:
                    logger.error(f"Connection failed with code {self.connect_rc} before timeout.")
                    self.disconnect()
                    return False
                time.sleep(0.1)

            if not self.is_connected:
                logger.error(f"Connection to {host}:{port} timed out after {timeout} seconds.")
                self.disconnect()
                return False
            return True
        except Exception as e:
            logger.error(f"Exception during MQTT connection to {host}:{port}: {e}")
            self.disconnect()
            return False

    def disconnect(self):
        """
        Disconnects the MQTT client from the broker.
        """
        if self.is_connected:
            self.client.loop_stop() # Stop the background thread
            self.client.disconnect()
            self.is_connected = False
            logger.info(f"Client {self.client_id} explicitly disconnected.")
        else:
            logger.debug(f"Client {self.client_id} was not connected.")

    def publish(self, topic: str, payload: str, qos: int = 0, retain: bool = False) -> bool:
        """
        Publishes a message to a given topic.

        Args:
            topic (str): The topic to publish to.
            payload (str): The message payload.
            qos (int): Quality of Service level (0, 1, or 2).
            retain (bool): Whether the message should be retained by the broker.

        Returns:
            bool: True if publish was successful, False otherwise.
        """
        if not self.is_connected:
            logger.warning(f"Cannot publish, client {self.client_id} is not connected.")
            return False
        try:
            info = self.client.publish(topic, payload, qos, retain)
            info.wait_for_publish() # Block until publish is complete
            logger.debug(f"Published to topic '{topic}' with payload '{payload}'.")
            return True
        except Exception as e:
            logger.error(f"Error publishing to topic '{topic}': {e}")
            return False

    def subscribe(self, topic: str, qos: int = 0) -> bool:
        """
        Subscribes to a given topic.

        Args:
            topic (str): The topic filter to subscribe to.
            qos (int): Quality of Service level (0, 1, or 2).

        Returns:
            bool: True if subscription was successful, False otherwise.
        """
        if not self.is_connected:
            logger.warning(f"Cannot subscribe, client {self.client_id} is not connected.")
            return False
        try:
            result, mid = self.client.subscribe(topic, qos)
            if result == mqtt.MQTT_ERR_SUCCESS:
                logger.debug(f"Subscribed to topic '{topic}'.")
                return True
            else:
                logger.error(f"Failed to subscribe to topic '{topic}', result: {result}")
                return False
        except Exception as e:
            logger.error(f"Error subscribing to topic '{topic}': {e}")
            return False

    def get_received_messages(self) -> list[Dict[str, Any]]:
        """
        Returns a list of messages received since the last call or initialization.
        """
        messages = self.messages_received
        self.messages_received = [] # Clear after retrieval
        return messages

    def set_will(self, topic: str, payload: str, qos: int = 0, retain: bool = False):
        """
        Sets the Last Will and Testament (LWT) message for the client.
        Must be called before connect().
        """
        self.client.will_set(topic, payload, qos, retain)
        logger.info(f"LWT set for topic '{topic}'.")

# Example Usage (for direct testing/demonstration)
if __name__ == "__main__":
    # This example requires an MQTT broker running at localhost:1883
    # and a config/settings.toml file in the parent directory.
    import sys
    import os

    # Setup basic logging for example
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Ensure config is loaded (adjust path if needed for direct run)
    try:
        # Adjust path for direct execution from this file
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config', 'settings.toml')
        app_config = Config(config_path=config_path)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n--- MQTT Client Wrapper Demonstration ---")

    # Test anonymous connection
    print("\nAttempting anonymous connection...")
    anon_client = MQTTClientWrapper("test_anon_client", app_config)
    if anon_client.connect(username=None, password=None):
        print("Anonymous connection successful.")
        anon_client.subscribe("test/topic")
        anon_client.publish("test/topic", "Hello from anonymous!")
        time.sleep(1) # Give time for message to arrive
        messages = anon_client.get_received_messages()
        if messages:
            print(f"Received: {messages[0]['payload']}")
        anon_client.disconnect()
    else:
        print("Anonymous connection failed.")

    # Test connection with credentials (if configured)
    print("\nAttempting connection with credentials...")
    user = app_config.get("credentials.username") or "testuser"
    passwd = app_config.get("credentials.password") or "testpass"
    cred_client = MQTTClientWrapper("test_cred_client", app_config)
    if cred_client.connect(username=user, password=passwd):
        print(f"Connection with {user}:{passwd} successful.")
        cred_client.publish("test/auth_topic", "Hello from authenticated!")
        cred_client.disconnect()
    else:
        print(f"Connection with {user}:{passwd} failed.")

    # Test LWT
    print("\nTesting Last Will and Testament (LWT)...")
    lwt_client = MQTTClientWrapper("test_lwt_client", app_config, clean_session=False)
    lwt_topic = app_config.get("topics.lwt_test_topic")
    lwt_payload = "LWT message: Client disconnected unexpectedly!"
    lwt_client.set_will(lwt_topic, lwt_payload, qos=1, retain=False)

    # Connect and then abruptly disconnect (simulate crash) to trigger LWT
    if lwt_client.connect(username=user, password=passwd):
        print(f"LWT client connected. Now simulating abrupt disconnect...")
        # To trigger LWT, we don't call disconnect() cleanly
        lwt_client.client.loop_stop()
        lwt_client.client.disconnect() # This will still send a DISCONNECT packet, but we want to simulate a network drop
        # For a true LWT test, you'd need to kill the process or simulate network failure
        # For this demo, we'll just show the setup.
        print(f"LWT message should be published to '{lwt_topic}' if client disconnects uncleanly.")
    else:
        print("LWT client connection failed.")
