import os
import subprocess
from flask import Flask, jsonify, request

FLAG_PATH = "/var/ctf/flag"

app = Flask(__name__)


def read_flag() -> str:
    with open(FLAG_PATH, "r", encoding="utf-8") as flag_file:
        return flag_file.read().strip()


@app.route("/")
def index():
    return (
        "Git-based CTF 테스트용 취약 서비스입니다. "
        "`/ping?host=<value>` 엔드포인트를 이용해 보세요."
    )


@app.route("/ping")
def ping():
    target = request.args.get("host", "127.0.0.1")
    try:
        completed = subprocess.check_output(
            f"ping -c 1 {target}",
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=3,
        )
        return jsonify({"output": completed.decode("utf-8")})
    except subprocess.CalledProcessError as exc:
        return jsonify({"error": exc.output.decode("utf-8")}), 400


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "flag_preview": read_flag()[:5] + "..."}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

