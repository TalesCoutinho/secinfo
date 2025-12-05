#!/usr/bin/env python3
import json
import csv
from pathlib import Path
from typing import Any, Dict, List

CAPTURA_FILE = "captura_tls.json"
TLS_RECORDS_CSV = "tls_records_parsed.csv"
TLS_FRAMES_CSV = "tls_frames_parsed.csv"


def load_packets(path: Path) -> List[Dict[str, Any]]:
    """Carrega o JSON exportado pelo tshark (-T json)."""
    if not path.exists():
        raise FileNotFoundError(f"Arquivo {path} não encontrado. Rode antes o tshark para gerar o JSON.")
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Formato inesperado de JSON: esperado uma lista de pacotes.")
    return data


def normalize_tls_records(tls_layer: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Normaliza o campo 'tls.record' para sempre retornar uma lista de records.
    No JSON do tshark, pode vir como dict (um só record) ou como lista.
    """
    if "tls.record" not in tls_layer:
        return []

    rec = tls_layer["tls.record"]
    if isinstance(rec, list):
        return rec
    elif isinstance(rec, dict):
        return [rec]
    else:
        return []


def map_tls_type_and_description(rec: Dict[str, Any]) -> (str, str):
    """
    Mapeia o tipo TLS (Handshake, ChangeCipherSpec, ApplicationData, Alert) e
    tenta gerar uma descrição mais amigável (ClientHello, ServerHello etc.).
    """
    content_type = rec.get("tls.record.content_type")
    opaque_type = rec.get("tls.record.opaque_type")

    # Em Application Data, o Wireshark usa 'opaque_type' = 23
    ctype = content_type or opaque_type

    ctype_map = {
        "20": "ChangeCipherSpec",
        "21": "Alert",
        "22": "Handshake",
        "23": "ApplicationData",
    }

    handshake_type_map = {
        "0": "HelloRequest",
        "1": "ClientHello",
        "2": "ServerHello",
        "11": "Certificate",
        "12": "ServerKeyExchange",
        "13": "CertificateRequest",
        "14": "ServerHelloDone",
        "16": "ClientKeyExchange",
        "20": "Finished",
    }

    tls_type = ""
    description = ""

    if ctype and ctype in ctype_map:
        tls_type = ctype_map[ctype]
    else:
        tls_type = ""

    # Se for handshake, tentar detalhar
    if tls_type == "Handshake" and "tls.handshake" in rec:
        hs = rec["tls.handshake"]
        hs_type = hs.get("tls.handshake.type")
        if hs_type and hs_type in handshake_type_map:
            description = handshake_type_map[hs_type]
        else:
            description = "Handshake"
    elif tls_type == "ChangeCipherSpec":
        description = "ChangeCipherSpec"
    elif tls_type == "ApplicationData":
        description = "Application Data"
    elif tls_type == "Alert":
        description = "Alert"

    return tls_type, description


def main():
    captura_path = Path(CAPTURA_FILE)
    packets = load_packets(captura_path)

    record_rows = []  # linhas por record TLS
    frame_rows = []   # linhas por frame

    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        frame = layers.get("frame", {})
        tcp = layers.get("tcp", {})
        tls = layers.get("tls")

        # Só nos interessam frames que têm camada TLS
        if tls is None:
            continue

        try:
            frame_no = int(frame.get("frame.number", "0"))
            frame_time = float(frame.get("frame.time_epoch", "0.0"))
            frame_len = int(frame.get("frame.len", "0"))
        except ValueError:
            # Se não conseguir converter, pula
            continue

        src_port = tcp.get("tcp.srcport")
        dst_port = tcp.get("tcp.dstport")

        # Normalizar records
        records = normalize_tls_records(tls)

        # Resumo para o frame (usamos o primeiro record para dar nome)
        frame_summary = ""
        if records:
            tls_type0, desc0 = map_tls_type_and_description(records[0])
            if tls_type0:
                if desc0:
                    frame_summary = f"{tls_type0} ({desc0})"
                else:
                    frame_summary = tls_type0
            else:
                frame_summary = "TLS record"
        else:
            frame_summary = "TLS (sem records)"

        frame_rows.append({
            "frame": frame_no,
            "time": frame_time,
            "len_bytes": frame_len,
            "src_port": src_port,
            "dst_port": dst_port,
            "tls_summary": frame_summary,
        })

        # Agora, uma linha por record dentro do frame
        for idx, rec in enumerate(records):
            tls_type, desc = map_tls_type_and_description(rec)
            rec_len_str = rec.get("tls.record.length") or rec.get("tls.record.len") or ""
            try:
                rec_len = int(rec_len_str) if rec_len_str != "" else ""
            except ValueError:
                rec_len = rec_len_str

            record_rows.append({
                "frame": frame_no,
                "record_index": idx,
                "time": frame_time,
                "len_bytes": frame_len,
                "src_port": src_port,
                "dst_port": dst_port,
                "tls_type": tls_type,
                "tls_record_len": rec_len,
                "description": desc,
            })

    # Ordenar por frame e índice de record
    record_rows.sort(key=lambda r: (r["frame"], r["record_index"]))
    frame_rows.sort(key=lambda r: r["frame"])

    # Impressão amigável no terminal
    print("\n===== REGISTROS TLS (uma linha por record) =====\n")
    if record_rows:
        header = ["frame", "record_index", "time", "len_bytes", "src_port", "dst_port",
                  "tls_type", "tls_record_len", "description"]
        print(f"{'frame':>6} {'record_index':>12} {'time':>12} {'len_bytes':>10} {'src_port':>8} {'dst_port':>8} {'tls_type':>12} {'tls_record_len':>14} description")
        for r in record_rows:
            print(f"{r['frame']:6} {r['record_index']:12} {r['time']:12.6e} {r['len_bytes']:10} "
                  f"{str(r['src_port']):>8} {str(r['dst_port']):>8} {r['tls_type']:>12} "
                  f"{str(r['tls_record_len']):>14} {r['description']}")
    else:
        print("Nenhum record TLS encontrado.")

    # Salvar CSV de records
    with open(TLS_RECORDS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "frame",
                "record_index",
                "time",
                "len_bytes",
                "src_port",
                "dst_port",
                "tls_type",
                "tls_record_len",
                "description",
            ],
        )
        writer.writeheader()
        for r in record_rows:
            writer.writerow(r)

    print(f"\nArquivo salvo: {TLS_RECORDS_CSV}")

    # Impressão amigável dos frames
    print("\n===== FRAMES TLS (uma linha por frame) =====\n")
    if frame_rows:
        print(f"{'frame':>6} {'time':>12} {'len_bytes':>10} {'src_port':>8} {'dst_port':>8} tls_summary")
        for r in frame_rows:
            print(f"{r['frame']:6} {r['time']:12.6e} {r['len_bytes']:10} "
                  f"{str(r['src_port']):>8} {str(r['dst_port']):>8} {r['tls_summary']}")
    else:
        print("Nenhum frame TLS encontrado.")

    # Salvar CSV de frames
    with open(TLS_FRAMES_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["frame", "time", "len_bytes", "src_port", "dst_port", "tls_summary"],
        )
        writer.writeheader()
        for r in frame_rows:
            writer.writerow(r)

    print(f"\nArquivo salvo: {TLS_FRAMES_CSV}")


if __name__ == "__main__":
    main()

