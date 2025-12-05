#!/usr/bin/env python3
import argparse
import socket
import struct
from pathlib import Path
import sys
import time
import csv
from datetime import datetime
import ssl

CHUNK_SIZE = 4096
RECEIVE_DIR = Path("received_tls")            # pasta onde os arquivos recebidos serão salvos
METRICS_FILE = Path("metrics_tls.csv")        # arquivo de métricas TLS
CERT_FILE = "certs/cert.pem"
KEY_FILE = "certs/key.pem"


def recv_exact(sock: socket.socket, n_bytes: int) -> bytes:
    """
    Lê exatamente n_bytes do socket.
    Se a conexão fechar antes, levanta exceção.
    """
    data = b""
    while len(data) < n_bytes:
        chunk = sock.recv(n_bytes - len(data))
        if not chunk:
            raise ConnectionError("Conexão fechada antes de receber todos os dados esperados.")
        data += chunk
    return data


def log_metrics(
    timestamp: str,
    client_ip: str,
    client_port: int,
    filename: str,
    file_size: int,
    duration: float,
) -> None:
    """
    Registra métricas de uma transferência em metrics_tls.csv.
    """
    throughput = file_size / duration if duration > 0 else 0.0

    file_exists = METRICS_FILE.exists()
    with METRICS_FILE.open("a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(
                [
                    "timestamp",
                    "client_ip",
                    "client_port",
                    "filename",
                    "file_size_bytes",
                    "duration_seconds",
                    "throughput_bytes_per_second",
                ]
            )
        writer.writerow(
            [
                timestamp,
                client_ip,
                client_port,
                filename,
                file_size,
                f"{duration:.6f}",
                f"{throughput:.6f}",
            ]
        )


def handle_client(conn: socket.socket, addr) -> None:
    """
    Lida com UM cliente TLS:
    - Lê header (tamanho do nome, nome, tamanho do arquivo)
    - Lê o conteúdo do arquivo
    - Salva o arquivo em disco
    - Registra métricas da transferência
    """
    print(f"[DEBUG] (TLS) Conexão recebida de {addr}")

    start_monotonic = time.perf_counter()
    timestamp = datetime.now().isoformat(timespec="seconds")

    # 1. Ler 2 bytes: tamanho do nome do arquivo
    raw_name_len = recv_exact(conn, 2)
    (name_len,) = struct.unpack("!H", raw_name_len)

    # 2. Ler nome do arquivo
    name_bytes = recv_exact(conn, name_len)
    filename = name_bytes.decode("utf-8", errors="replace")

    # 3. Ler 8 bytes: tamanho do arquivo
    raw_file_size = recv_exact(conn, 8)
    (file_size,) = struct.unpack("!Q", raw_file_size)

    print(f"[DEBUG] (TLS) Recebendo arquivo '{filename}' ({file_size} bytes)...")

    # 4. Garantir que a pasta de destino existe
    RECEIVE_DIR.mkdir(parents=True, exist_ok=True)
    dest_path = RECEIVE_DIR / filename

    # 5. Ler o conteúdo do arquivo em chunks e salvar
    bytes_remaining = file_size
    with dest_path.open("wb") as f:
        while bytes_remaining > 0:
            to_read = min(CHUNK_SIZE, bytes_remaining)
            chunk = recv_exact(conn, to_read)
            f.write(chunk)
            bytes_remaining -= len(chunk)

    duration = time.perf_counter() - start_monotonic

    print(f"[DEBUG] (TLS) Arquivo salvo em: {dest_path.resolve()}")
    print(f"[DEBUG] (TLS) Duração da transferência: {duration:.6f} s")
    print("[DEBUG] (TLS) Registrando métricas...\n")

    client_ip, client_port = addr
    log_metrics(timestamp, client_ip, client_port, filename, file_size, duration)


def parse_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Servidor TCP com TLS para receber arquivo."
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Endereço onde o servidor irá escutar (padrão: 0.0.0.0)",
    )
    parser.add_argument(
        "port",
        type=int,
        help="Porta onde o servidor irá escutar (ex.: 5001)",
    )
    return parser


def main() -> None:
    print("[DEBUG] Iniciando servidor_tls.py...")

    parser = parse_args()
    args = parser.parse_args()
    host = args.host
    port = args.port

    # Criar contexto TLS de servidor
    print(f"[DEBUG] Carregando certificado: {CERT_FILE} e chave: {KEY_FILE}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    print(f"[DEBUG] Criando socket em {host}:{port} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(5)

        print(f"Servidor TLS ouvindo em {host}:{port}")
        print(f"Arquivos recebidos serão salvos na pasta: {RECEIVE_DIR}/")
        print(f"Métricas TLS serão salvas em: {METRICS_FILE}\n")

        while True:
            print("[DEBUG] (TLS) Aguardando conexão...")
            conn, addr = server_sock.accept()
            try:
                # Envelopa a conexão TCP em TLS
                with context.wrap_socket(conn, server_side=True) as tls_conn:
                    handle_client(tls_conn, addr)
            except Exception as e:
                print(f"[ERRO] (TLS) Ao lidar com {addr}: {e}", file=sys.stderr)
                conn.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERRO FATAL] {e}", file=sys.stderr)
        sys.exit(1)

