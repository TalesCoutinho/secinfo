#!/usr/bin/env python3
import json
import csv
from pathlib import Path
from typing import Any, Dict, List

CAPTURA_FILE = "captura_tcp.json"
TCP_FRAMES_CSV = "tcp_frames_parsed.csv"


def load_packets(path: Path) -> List[Dict[str, Any]]:
    """Carrega o JSON exportado pelo tshark (-T json)."""
    if not path.exists():
        raise FileNotFoundError(f"Arquivo {path} não encontrado. Rode antes o tshark para gerar o JSON.")
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Formato inesperado de JSON: esperado uma lista de pacotes.")
    return data


def parse_tcp_flags(tcp_layer: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extrai flags do TCP e monta:
      - string tipo 'SYN', 'SYN,ACK', 'PSH,ACK', etc.
      - descrição mais amigável do papel do pacote.
    """
    flags_tree = tcp_layer.get("tcp.flags_tree", {})
    flag_syn  = flags_tree.get("tcp.flags.syn")  == "1"
    flag_ack  = flags_tree.get("tcp.flags.ack")  == "1"
    flag_fin  = flags_tree.get("tcp.flags.fin")  == "1"
    flag_rst  = flags_tree.get("tcp.flags.reset") == "1"
    flag_psh  = flags_tree.get("tcp.flags.push") == "1"

    # Monta string de flags (ordem clássica)
    parts = []
    if flag_syn:
        parts.append("SYN")
    if flag_fin:
        parts.append("FIN")
    if flag_rst:
        parts.append("RST")
    if flag_psh:
        parts.append("PSH")
    if flag_ack:
        parts.append("ACK")

    flags_str = ",".join(parts) if parts else ""

    # Descrição amigável
    desc = ""
    if flag_syn and not flag_ack:
        desc = "SYN (início de conexão)"
    elif flag_syn and flag_ack:
        desc = "SYN,ACK (resposta do servidor)"
    elif flag_fin and flag_ack:
        desc = "FIN,ACK (encerrando conexão)"
    elif flag_rst:
        desc = "RST (reset de conexão)"
    elif flag_psh and flag_ack:
        desc = "PSH,ACK (dados + ACK)"
    elif flag_ack and not (flag_syn or flag_fin or flag_rst or flag_psh):
        desc = "ACK (confirmação)"
    else:
        desc = flags_str or "Pacote TCP"

    return {
        "flags_str": flags_str,
        "description": desc,
    }


def main():
    captura_path = Path(CAPTURA_FILE)
    packets = load_packets(captura_path)

    frame_rows = []

    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        frame = layers.get("frame", {})
        tcp = layers.get("tcp")

        # Só nos interessam frames que têm camada TCP
        if tcp is None:
            continue

        try:
            frame_no = int(frame.get("frame.number", "0"))
            frame_time = float(frame.get("frame.time_epoch", "0.0"))
            frame_len = int(frame.get("frame.len", "0"))
        except ValueError:
            continue

        src_port = tcp.get("tcp.srcport")
        dst_port = tcp.get("tcp.dstport")

        # Comprimento de payload TCP (campo tcp.len no tshark)
        try:
            tcp_len = int(tcp.get("tcp.len", "0"))
        except ValueError:
            tcp_len = 0

        flags_info = parse_tcp_flags(tcp)
        flags_str = flags_info["flags_str"]
        desc = flags_info["description"]

        # RTT (se existir)
        analysis = tcp.get("tcp.analysis", {})
        ack_rtt = analysis.get("tcp.analysis.ack_rtt")
        init_rtt = analysis.get("tcp.analysis.initial_rtt")

        frame_rows.append({
            "frame": frame_no,
            "time": frame_time,
            "len_bytes": frame_len,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_payload_len": tcp_len,
            "flags": flags_str,
            "description": desc,
            "ack_rtt": ack_rtt,
            "initial_rtt": init_rtt,
        })

    # Ordenar por número de frame
    frame_rows.sort(key=lambda r: r["frame"])

    # Impressão amigável
    print("\n===== FRAMES TCP (handshake, dados, encerramento) =====\n")
    if frame_rows:
        print(f"{'frame':>6} {'time':>12} {'len_bytes':>10} {'src_port':>8} {'dst_port':>8} "
              f"{'payload':>8} {'flags':>10}  descrição")
        for r in frame_rows:
            print(
                f"{r['frame']:6} {r['time']:12.6e} {r['len_bytes']:10} "
                f"{str(r['src_port']):>8} {str(r['dst_port']):>8} "
                f"{r['tcp_payload_len']:8} {r['flags']:>10}  {r['description']}"
            )
    else:
        print("Nenhum frame TCP encontrado.")

    # Salvar CSV
    with open(TCP_FRAMES_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "frame",
                "time",
                "len_bytes",
                "src_port",
                "dst_port",
                "tcp_payload_len",
                "flags",
                "description",
                "ack_rtt",
                "initial_rtt",
            ],
        )
        writer.writeheader()
        for r in frame_rows:
            writer.writerow(r)

    print(f"\nArquivo salvo: {TCP_FRAMES_CSV}")


if __name__ == "__main__":
    main()

