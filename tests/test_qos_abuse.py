import unittest
from unittest.mock import patch, call
from mqtt_security_tester.main import test_qos_abuse

class TestQosAbuse(unittest.TestCase):

    @patch('mqtt_security_tester.main.mqtt.Client')
    def test_qos_abuse(self, mock_client):
        broker = "test.mosquitto.org"
        test_qos_abuse(broker, None)

        instance = mock_client.return_value
        instance.connect.assert_called_once_with(broker, 1883, 60)
        self.assertEqual(instance.publish.call_count, 100)
        instance.publish.assert_has_calls([call("test/qos", "test_message", qos=2)] * 100)
        instance.disconnect.assert_called_once()

if __name__ == '__main__':
    unittest.main()
