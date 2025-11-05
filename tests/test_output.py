import unittest
import os
from mqtt_security_tester.main import test_anonymous_connection

class TestOutput(unittest.TestCase):

    def test_save_output(self):
        broker = "test.mosquitto.org"
        output_file = "test_output.txt"

        # Ensure the file does not exist before the test
        if os.path.exists(output_file):
            os.remove(output_file)

        test_anonymous_connection(broker, output_file)

        self.assertTrue(os.path.exists(output_file))

        with open(output_file, "r") as f:
            content = f.read()
            self.assertIn(f"[+] Anonymous connection to {broker} successful.", content)

        # Clean up the file after the test
        os.remove(output_file)

if __name__ == '__main__':
    unittest.main()
