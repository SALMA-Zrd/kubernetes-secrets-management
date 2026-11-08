import json
import os
from pathlib import Path

from flask import Flask, jsonify
import psycopg2
from psycopg2 import OperationalError

app = Flask(__name__)

VAULT_SECRET_FILE = Path("/vault/secrets/db.json")

REQUIRED_KEYS = (
    "DB_HOST",
    "DB_PORT",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
)


def load_db_config():
    backend = os.getenv("SECRETS_BACKEND", "native")

    if backend == "vault":
        with VAULT_SECRET_FILE.open(
            "r", encoding="utf-8"
        ) as file:
            config = json.load(file)

    elif backend == "native":
        config = {
            key: os.environ[key]
            for key in REQUIRED_KEYS
        }

    else:
        raise ValueError("Unsupported secrets backend")

    if not isinstance(config, dict):
        raise ValueError("Invalid database configuration")

    if any(
        not isinstance(config.get(key), str)
        or not config[key]
        for key in REQUIRED_KEYS
    ):
        raise ValueError("Missing database configuration")

    return config


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.get("/db-check")
def db_check():
    connection = None

    try:
        config = load_db_config()

        connection = psycopg2.connect(
            host=config["DB_HOST"],
            port=int(config["DB_PORT"]),
            dbname=config["DB_NAME"],
            user=config["DB_USER"],
            password=config["DB_PASSWORD"],
            connect_timeout=5,
        )

        with connection.cursor() as cursor:
            cursor.execute("SELECT 1;")
            cursor.fetchone()

        return jsonify({
            "status": "success",
            "database": "connected"
        }), 200

    except (
        OperationalError,
        KeyError,
        ValueError,
        OSError,
        json.JSONDecodeError,
    ):
        app.logger.warning(
            "Database connection check failed"
        )

        return jsonify({
            "status": "error",
            "database": "unavailable"
        }), 503

    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
