import logging
from typing import Optional

try:
    from confluent_kafka import Producer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

logger = logging.getLogger("BSES.KafkaStream")

class KafkaStream:
    def __init__(self, bootstrap_servers: str = "localhost:9092", topic: str = "bank-security-logs"):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.producer: Optional[Producer] = None
        self.enabled = KAFKA_AVAILABLE
        self._poll_counter = 0

    def connect(self):
        if not self.enabled:
            logger.warning("confluent-kafka package not installed. Kafka output will be inactive.")
            return
        
        try:
            # High throughput configuration params
            config = {
                'bootstrap.servers': self.bootstrap_servers,
                'queue.buffering.max.messages': 200000,
                'queue.buffering.max.ms': 50,  # low latency batching
                'linger.ms': 5,
                'acks': 1,
                'compression.type': 'lz4'      # high speed compression
            }
            self.producer = Producer(config)
            logger.info(f"Kafka Producer initialized. Target Servers: {self.bootstrap_servers}, Topic: {self.topic}")
        except Exception as e:
            logger.error(f"Failed to initialize Kafka client: {e}")
            self.producer = None

    def _delivery_report(self, err, msg):
        if err is not None:
            logger.error(f"Kafka message delivery failed: {err}")

    def emit(self, message: str):
        if not self.producer:
            return

        try:
            self.producer.produce(
                self.topic,
                value=message.encode('utf-8'),
                callback=self._delivery_report
            )
            
            # Poll regularly but not on every single message to optimize CPU usage
            self._poll_counter += 1
            if self._poll_counter % 100 == 0:
                self.producer.poll(0)
                self._poll_counter = 0
        except Exception as e:
            logger.error(f"Error producing payload to Kafka topic {self.topic}: {e}")

    def flush(self):
        if self.producer:
            logger.info("Flushing remaining Kafka messages...")
            self.producer.flush(timeout=5.0)

    def close(self):
        self.flush()
        self.producer = None
