import unittest
from unittest.mock import patch
from mqtt_security_tester.main import test_anonymous_connection as _mqtt_anonymous_connection

class TestConnection(unittest.TestCase):

    @patch('mqtt_security_tester.main.mqtt.Client')
    def test_anonymous_connection_success(self, mock_client):
        broker = "test.mosquitto.org"
        _mqtt_anonymous_connection(broker, None)
        mock_client.assert_called_once()
        instance = mock_client.return_value
        instance.connect.assert_called_once_with(broker, 1883, 60)
        instance.disconnect.assert_called_once()

if __name__ == '__main__':
    unittest.main()
