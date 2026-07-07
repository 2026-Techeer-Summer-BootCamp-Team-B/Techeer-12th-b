
import os
import json
import time
import random
from datetime import datetime
from kafka import KafkaProducer
from faker import Faker

# 1. Configuration
KAFKA_BROKER = os.getenv('KAFKA_BROKER', 'localhost:9092')
KAFKA_TOPIC = os.getenv('KAFKA_TOPIC', 'security_events')
EVENTS_PER_SECOND = int(os.getenv('EVENTS_PER_SECOND', '5')) # Default to 5 events per second

fake = Faker()

# Kafka Producer initialization
producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

def generate_waf_event():
    """Generates a WAF block event JSON."""
    timestamp = datetime.now().isoformat()
    client_ip = fake.ipv4()
    request_uri = fake.uri_path()
    block_reasons = ["SQL Injection", "XSS", "Path Traversal", "Remote Code Execution", "Malicious User-Agent"]
    block_reason = random.choice(block_reasons)

    event = {
        "timestamp": timestamp,
        "client_ip": client_ip,
        "request_uri": request_uri,
        "block_reason": block_reason,
        "action": "blocked"
    }
    return event

def generate_falco_event():
    """Generates a Falco-like detection event JSON."""
    timestamp = datetime.now().isoformat()
    rule_names = [
        "Unauthorized File Modification",
        "Terminal shell in container",
        "Sensitive file accessed",
        "Network connection from untrusted source",
        "Privilege escalation attempt"
    ]
    rule = random.choice(rule_names)
    priority = random.choice(["Critical", "High", "Medium", "Low"])
    output = f"Rule '{rule}' triggered by user {fake.user_name()} on host {fake.hostname()} with IP {fake.ipv4()}."

    event = {
        "agent": "log-analyzer", # Core requirement
        "timestamp": timestamp,
        "rule": rule,
        "priority": priority,
        "output": output
    }
    return event

def send_event(event):
    """Sends a single event to Kafka."""
    try:
        producer.send(KAFKA_TOPIC, event)
        print(f"Sent event: {json.dumps(event)}")
    except Exception as e:
        print(f"Error sending event: {e}")

def main():
    print(f"Starting dummy event generator for Kafka broker: {KAFKA_BROKER}, topic: {KAFKA_TOPIC}")
    print(f"Generating {EVENTS_PER_SECOND} events per second...")

    event_counter = 0
    start_time = time.time()

    while True:
        if event_counter >= EVENTS_PER_SECOND:
            elapsed_time = time.time() - start_time
            if elapsed_time < 1.0:
                time.sleep(1.0 - elapsed_time)
            event_counter = 0
            start_time = time.time()

        # Randomly choose event type (8:2 ratio for WAF:Falco)
        if random.random() < 0.8: # 80% chance for WAF
            event = generate_waf_event()
        else: # 20% chance for Falco
            event = generate_falco_event()

        send_event(event)
        event_counter += 1

if __name__ == "__main__":
    main()
