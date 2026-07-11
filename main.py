import asyncio
import argparse
import sys
import signal
import logging
import uvicorn
from src.core.state import StateStore
from src.agents.compiler import PersonaCompiler
from src.core.engine import SimulationEngine
from src.outputs.syslog_stream import SyslogStream
from src.outputs.kafka_stream import KafkaStream
from src.core.web_app import app as web_app, setup_websocket_callback


# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("BSES.Main")

class ConsoleSummaryEmitter:
    """A high-performance console logger that samples log emission to prevent stdout bottlenecks."""
    def __init__(self, sample_rate: float = 0.001):
        self.sample_rate = sample_rate

    def emit(self, message: str):
        # Sample logs to avoid slowing down execution
        if self.sample_rate > 0 and type(self.sample_rate) == float:
            import random
            if random.random() < self.sample_rate:
                logger.info(f"Sampled Event Log: {message[:120]}...")

def shutdown_handler(engine):
    logger.info("Termination signal received. Initiating graceful shutdown...")
    engine.stop()


async def main():
    parser = argparse.ArgumentParser(description="Banking Security Environment Simulator (BSES)")
    parser.add_argument("--redis-url", type=str, default="redis://localhost:6379/0", help="Redis URL (redis://host:port/db)")
    parser.add_argument("--syslog-host", type=str, default="127.0.0.1", help="Target Syslog UDP host")
    parser.add_argument("--syslog-port", type=int, default=514, help="Target Syslog UDP port")
    parser.add_argument("--kafka-servers", type=str, default=None, help="Kafka bootstrap servers (e.g. localhost:9092)")
    parser.add_argument("--kafka-topic", type=str, default="bank-security-logs", help="Kafka topic for emitted logs")
    parser.add_argument("--eps", type=int, default=1000, help="Target Events Per Second (EPS)")
    parser.add_argument("--attack-rate", type=float, default=0.05, help="Ratio of threat injection actions (0.0 to 1.0)")
    parser.add_argument("--compile-personas", action="store_true", help="Compile and refresh Markov transition tables in Redis")
    parser.add_argument("--verbose", action="store_true", help="Print all logs to console stdout (warning: will limit EPS performance)")
    parser.add_argument("--web-host", type=str, default="127.0.0.1", help="Web portal server host")
    parser.add_argument("--web-port", type=int, default=8000, help="Web portal server port")
    args = parser.parse_args()

    logger.info("Starting Banking Security Environment Simulator (BSES)")

    # 1. State Store Connection
    store = StateStore(args.redis_url)
    await store.connect()

    # 2. Seeding / Persona Compiling
    compiler = PersonaCompiler(store)
    # Automatically seed Redis if requested or if Markov tables are missing
    check_chain = await store.get_markov_chain("regular_customer")
    if args.compile_personas or not check_chain:
        logger.info("No Markov persona tables found or compile flag set. Initiating offline LLM compilation phase...")
        await compiler.compile_all_and_cache()

    # 3. Setup output emitters
    emitters = []
    
    # Sample console printing (or verbose printing)
    sample_rate = 1.0 if args.verbose else 0.001
    logger.info(f"Registering Console Summary Emitter (Sampling: {sample_rate*100}%)")
    emitters.append(ConsoleSummaryEmitter(sample_rate=sample_rate))

    # Syslog
    logger.info(f"Registering UDP Syslog Stream -> {args.syslog_host}:{args.syslog_port}")
    syslog = SyslogStream(host=args.syslog_host, port=args.syslog_port)
    await syslog.connect()
    emitters.append(syslog)

    # Kafka
    if args.kafka_servers:
        logger.info(f"Registering Kafka Stream -> {args.kafka_servers} (Topic: {args.kafka_topic})")
        kafka = KafkaStream(bootstrap_servers=args.kafka_servers, topic=args.kafka_topic)
        kafka.connect()
        emitters.append(kafka)

    # 4. Engine Bootstrapping
    engine = SimulationEngine(
        infra_config_path="config/infrastructure.yaml",
        attack_db_path="config/attack_db.json",
        state_store=store,
        emitters=emitters,
        target_eps=args.eps,
        attack_rate=args.attack_rate
    )
    await engine.load_configurations()
    await engine.initialize_state_machines()
    engine.build_entity_pools()
    
    # Register web log stream callbacks
    setup_websocket_callback(engine)

    # 5. Handle process interrupts cleanly
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: shutdown_handler(engine))
        except NotImplementedError:
            # Signal handlers not implemented on Windows event loops
            pass

    # 6. Run web app server & simulator core concurrently
    config = uvicorn.Config(web_app, host=args.web_host, port=args.web_port, log_level="warning")
    server = uvicorn.Server(config)

    try:
        await asyncio.gather(
            engine.start(),
            server.serve()
        )
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        # Final cleanup safety net
        logger.info("Shutting down core engine...")
        engine.stop()
        await store.close()
        for emitter in emitters:
            if hasattr(emitter, "close"):
                emitter.close()

if __name__ == "__main__":
    asyncio.run(main())
