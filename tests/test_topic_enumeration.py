import unittest
from unittest.mock import patch, call
from mqtt_security_tester.main import test_topic_enumeration

class TestTopicEnumeration(unittest.TestCase):

    @patch('mqtt_security_tester.main.mqtt.Client')
    def test_topic_enumeration(self, mock_client):
        broker = "test.mosquitto.org"
        test_topic_enumeration(broker, None)

        instance = mock_client.return_value
        self.assertEqual(instance.subscribe.call_count, 4)
        instance.subscribe.assert_has_calls([
            call("#"),
            call("$SYS/#"),
            call("test"),
            call("topic/test"),
        ])
        self.assertEqual(instance.connect.call_count, 4)
        instance.connect.assert_has_calls([
            call(broker, 1883, 60),
            call(broker, 1883, 60),
            call(broker, 1883, 60),
            call(broker, 1883, 60),
        ])
        self.assertEqual(instance.disconnect.call_count, 4)

if __name__ == '__main__':
    unittest.main()
