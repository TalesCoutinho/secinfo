#!/usr/bin/env python3
import argparse
import socket
import struct
import sys
import time
from pathlib import Path

CHUNK_SIZE = 4096


def send_file(host: str, port: int, filepath: str) -> None:
    """
    Envia um arquivo para o servidor usando TCP (sem TLS),
    seguindo o protocolo:
      [2 bytes] len(nome_arquivo)
      [len bytes] nome_arquivo (UTF-8)
      [8 bytes] tamanho_arquivo (em bytes)
      [tamanho_arquivo bytes] conteúdo do arquivo
    """
    path = Path(filepath)

    if not path.is_file():
        raise FileNotFoundError(f"Arquivo não encontrado: {filepath}")

    filename = path.name
    name_bytes = filename.encode("utf-8")
    name_len = len(name_bytes)

    if name_len > 65535:
        raise ValueError("Nome do arquivo muito grande (máx. 65535 bytes em UTF-8).")

    file_size = path.stat().st_size

    header = struct.pack("!H", name_len) + name_bytes + struct.pack("!Q", file_size)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"Conectando a {host}:{port} ...")
        sock.connect((host, port))
        print("Conexão estabelecida.")

        print(f"Enviando arquivo '{filename}' ({file_size} bytes)...")
        sock.sendall(header)

        total_sent = 0
        with path.open("rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sock.sendall(chunk)
                total_sent += len(chunk)

        print("Envio concluído com sucesso.\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cliente TCP simples para envio de arquivo (sem TLS)."
    )
    parser.add_argument("host", help="Endereço IP ou hostname do servidor (ex.: 127.0.0.1)")
    parser.add_argument("port", type=int, help="Porta do servidor (ex.: 5000)")
    parser.add_argument(
        "filepath",
        help="Caminho do arquivo a ser enviado (ex.: files/arquivo.txt)",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Número de vezes que o arquivo será enviado (padrão: 1)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    for i in range(1, args.repeat + 1):
        print(f"=== Envio {i}/{args.repeat} ===")
        start = time.perf_counter()
        try:
            send_file(args.host, args.port, args.filepath)
        except Exception as e:
            print(f"Erro no envio {i}: {e}", file=sys.stderr)
            sys.exit(1)
        duration = time.perf_counter() - start
        print(f"Tempo medido no cliente: {duration:.6f} s\n")


if __name__ == "__main__":
    main()

