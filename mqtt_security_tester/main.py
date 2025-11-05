import paho.mqtt.client as mqtt
import argparse

import sys

def save_output(file, message):
    if file:
        with open(file, "a") as f:
            f.write(message + "\n")
    else:
        print(message)

def test_anonymous_connection(broker, output_file):
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.connect(broker, 1883, 60)
        save_output(output_file, f"[+] Anonymous connection to {broker} successful.")
        client.disconnect()
    except Exception as e:
        save_output(output_file, f"[-] Anonymous connection to {broker} failed: {e}")

def test_default_credentials(broker, output_file):
    default_creds = [
        ("admin", "admin"),
        ("user", "user"),
        ("guest", "guest"),
    ]

    for username, password in default_creds:
        try:
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
            client.username_pw_set(username, password)
            client.connect(broker, 1883, 60)
            save_output(output_file, f"[+] Connection with {username}:{password} successful.")
            client.disconnect()
        except Exception as e:
            save_output(output_file, f"[-] Connection with {username}:{password} failed: {e}")

def test_topic_enumeration(broker, output_file):
    common_topics = [
        "#",
        "$SYS/#",
        "test",
        "topic/test",
    ]

    for topic in common_topics:
        try:
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
            client.connect(broker, 1883, 60)
            client.subscribe(topic)
            save_output(output_file, f"[+] Subscription to {topic} successful.")
            client.disconnect()
        except Exception as e:
            save_output(output_file, f"[-] Subscription to {topic} failed: {e}")

def test_qos_abuse(broker, output_file):
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.connect(broker, 1883, 60)
        save_output(output_file, "[+] Connected for QoS abuse test.")
        for i in range(100):
            client.publish("test/qos", "test_message", qos=2)
        save_output(output_file, "[+] Sent 100 messages with QoS 2.")
        client.disconnect()
    except Exception as e:
        save_output(output_file, f"[-] QoS abuse test failed: {e}")

def test_large_message(broker, output_file):
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.connect(broker, 1883, 60)
        save_output(output_file, "[+] Connected for large message test.")
        large_message = "a" * 1000000
        client.publish("test/large_message", large_message)
        save_output(output_file, "[+] Sent a 1MB message.")
        client.disconnect()
    except Exception as e:
        save_output(output_file, f"[-] Large message test failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT Security Tester")
    parser.add_argument("broker", help="The MQTT broker to test")
    parser.add_argument("-o", "--output", help="Save the output to a file")
    args = parser.parse_args()

    test_anonymous_connection(args.broker, args.output)
    test_default_credentials(args.broker, args.output)
    test_topic_enumeration(args.broker, args.output)
    test_qos_abuse(args.broker, args.output)
    test_large_message(args.broker, args.output)
