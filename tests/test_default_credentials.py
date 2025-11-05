import unittest
from unittest.mock import patch, call
from mqtt_security_tester.main import test_default_credentials

class TestDefaultCredentials(unittest.TestCase):

    @patch('mqtt_security_tester.main.mqtt.Client')
    def test_default_credentials(self, mock_client):
        broker = "test.mosquitto.org"
        test_default_credentials(broker, None)

        instance = mock_client.return_value
        self.assertEqual(instance.username_pw_set.call_count, 3)
        instance.username_pw_set.assert_has_calls([
            call("admin", "admin"),
            call("user", "user"),
            call("guest", "guest"),
        ])
        self.assertEqual(instance.connect.call_count, 3)
        instance.connect.assert_has_calls([
            call(broker, 1883, 60),
            call(broker, 1883, 60),
            call(broker, 1883, 60),
        ])
        self.assertEqual(instance.disconnect.call_count, 3)

if __name__ == '__main__':
    unittest.main()
