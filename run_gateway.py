#!/usr/bin/env python3
"""
AgentWacht - Launcher
=====================
Simple launcher script for the AgentWacht gateway.

Usage:
    python run_gateway.py [--config path/to/policy.yaml] [--port 8000]

Environment Variables:
    GATEWAY_PORT: Port to listen on (default: 8000)
    GATEWAY_CONFIG: Path to YAML config file (default: policy.yaml)

Examples:
    # Basic usage with default config
    python run_gateway.py

    # Custom config and port
    python run_gateway.py --config my_config.yaml --port 9000

    # Using environment variables
    export GATEWAY_CONFIG=production_policy.yaml
    export GATEWAY_PORT=443
    python run_gateway.py
"""

import argparse
import logging
import os
import socket
import sys
from pathlib import Path

import uvicorn


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="AgentWacht — Zero Trust Proxy for the Model Context Protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--config",
        type=str,
        default=os.environ.get("GATEWAY_CONFIG", "policy.yaml"),
        help="Path to YAML configuration file (default: policy.yaml)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("GATEWAY_PORT", 8000)),
        help="Port to listen on (default: 8000)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=os.environ.get("GATEWAY_HOST", "0.0.0.0"),
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development (default: False)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["debug", "info", "warning", "error"],
        default="info",
        help="Logging level (default: info)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)",
    )

    return parser.parse_args()


def validate_config(config_path: str) -> bool:
    """Validate that the configuration file exists and is readable."""
    path = Path(config_path)

    if not path.exists():
        logging.error("Configuration file not found: %s", config_path)
        return False

    if not path.is_file():
        logging.error("Configuration path is not a file: %s", config_path)
        return False

    if path.suffix not in (".yaml", ".yml"):
        logging.warning("Configuration file does not have .yaml/.yml extension: %s", config_path)

    try:
        import yaml

        with open(path, "r") as f:
            config = yaml.safe_load(f)

        required_sections = ["upstream_servers", "users", "roles", "policies", "gateway_settings"]
        for section in required_sections:
            if section not in config:
                logging.error("Missing required section in config: %s", section)
                return False

        logging.info(
            "Configuration validated: %d upstreams, %d users",
            len(config["upstream_servers"]),
            len(config["users"]),
        )
        return True

    except Exception as e:
        logging.error("Failed to parse configuration file: %s", e)
        return False


def main():
    """Main entry point."""
    args = parse_args()

    log_level = getattr(logging, args.log_level.upper())
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger = logging.getLogger("agentwacht")

    logger.info("=" * 60)
    logger.info("AgentWacht — Zero Trust Proxy for MCP")
    logger.info("https://github.com/8peaks/agentwacht")
    logger.info("=" * 60)

    logger.info("Loading configuration from: %s", args.config)
    if not validate_config(args.config):
        logger.error("Configuration validation failed. Exiting.")
        sys.exit(1)

    os.environ["GATEWAY_CONFIG"] = args.config
    os.environ["GATEWAY_PORT"] = str(args.port)

    logger.info("Host: %s", args.host)
    logger.info("Port: %s", args.port)
    logger.info("Workers: %s", args.workers)
    logger.info("Auto-reload: %s", args.reload)
    logger.info("Log level: %s", args.log_level)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(("127.0.0.1" if args.host == "0.0.0.0" else args.host, args.port))
    sock.close()

    if result == 0:
        logger.warning("Port %s is already in use!", args.port)
        logger.error("Cannot start gateway. Please choose a different port or stop the conflicting service.")
        sys.exit(1)

    logger.info("Starting gateway...")
    logger.info("Access the gateway at: http://%s:%s", args.host, args.port)
    logger.info("Health check: http://%s:%s/health", args.host, args.port)
    logger.info("Admin dashboard: http://%s:%s/admin", args.host, args.port)
    logger.info("=" * 60)

    try:
        uvicorn.run(
            "gateway_core:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            workers=args.workers if not args.reload else 1,
            log_level=args.log_level,
            access_log=True,
            server_header=False,
            date_header=False,
        )
    except KeyboardInterrupt:
        logger.info("\nReceived shutdown signal (Ctrl+C)")
        logger.info("Gateway stopped.")
        sys.exit(0)
    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
