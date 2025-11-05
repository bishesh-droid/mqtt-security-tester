import unittest
from unittest.mock import patch, call
from mqtt_security_tester.main import test_large_message

class TestLargeMessage(unittest.TestCase):

    @patch('mqtt_security_tester.main.mqtt.Client')
    def test_large_message(self, mock_client):
        broker = "test.mosquitto.org"
        test_large_message(broker, None)

        instance = mock_client.return_value
        instance.connect.assert_called_once_with(broker, 1883, 60)
        instance.publish.assert_called_once_with("test/large_message", "a" * 1000000)
        instance.disconnect.assert_called_once()

if __name__ == '__main__':
    unittest.main()
