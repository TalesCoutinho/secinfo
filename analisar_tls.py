#!/usr/bin/env python3
import json
import pandas as pd

# Mapeamento numérico → nome do registro TLS
TLS_TYPE = {
    "20": "Change Cipher Spec",
    "21": "Alert",
    "22": "Handshake",
    "23": "Application Data",
}

HANDSHAKE_TYPE = {
    "1": "ClientHello",
    "2": "ServerHello",
    "11": "Certificate",
    "12": "ServerKeyExchange",
    "14": "ServerHelloDone",
    "16": "ClientKeyExchange",
    "20": "Finished",
}


def get_first(val):
    """
    No JSON do tshark, alguns campos vêm como lista, outros como string.
    Essa função normaliza:
      - se for lista → pega o primeiro elemento
      - caso contrário → devolve como está
    """
    if isinstance(val, list):
        return val[0] if val else ""
    return val


def load_tls_json(path="captura_tls.json"):
    with open(path, "r") as f:
        return json.load(f)


def extract_records(capture):
    """
    Extrai uma linha por *registro TLS* dentro de cada frame.
    Se um frame tiver 3 registros TLS, ele gera 3 linhas.
    """
    rows = []

    for packet in capture:
        layers = packet.get("_source", {}).get("layers", {})

        frame = layers.get("frame", {})
        frame_num = get_first(frame.get("frame.number", ""))
        frame_len = get_first(frame.get("frame.len", ""))
        timestamp = get_first(frame.get("frame.time_epoch", ""))

        tcp_info = layers.get("tcp", {})
        src_port = get_first(tcp_info.get("tcp.srcport", ""))
        dst_port = get_first(tcp_info.get("tcp.dstport", ""))

        tls_info = layers.get("tls")
        if not tls_info:
            # não há TLS nesse frame; ainda podemos registrar só para contexto se quisermos
            continue

        recs = tls_info.get("tls.record")
        if not recs:
            continue

        # tls.record pode ser dict (1 só) ou lista (vários)
        if isinstance(recs, dict):
            recs = [recs]

        for idx, rec in enumerate(recs):
            # Tipo do registro TLS (Handshake, Application Data, etc.)
            record_type_num = get_first(rec.get("tls.record.content_type", ""))
            tls_type = TLS_TYPE.get(record_type_num, record_type_num)

            record_len = get_first(rec.get("tls.record.length", ""))

            # Handshake interno (se houver)
            desc = ""
            hs = rec.get("tls.handshake")
            if isinstance(hs, list):
                # vários handshakes no mesmo registro → pega o primeiro só pra resumo
                hs = hs[0]
            if isinstance(hs, dict):
                hs_type_num = get_first(hs.get("tls.handshake.type", ""))
                desc = HANDSHAKE_TYPE.get(hs_type_num, "")

            # Se não tem handshake mas é Application Data, rotulamos como criptografado
            if tls_type == "Application Data" and not desc:
                desc = "Encrypted Application Data"

            rows.append(
                {
                    "frame": int(frame_num) if str(frame_num).isdigit() else frame_num,
                    "record_index": idx,
                    "time": float(timestamp) if timestamp not in ("", None) else None,
                    "len_bytes": int(frame_len) if str(frame_len).isdigit() else frame_len,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "tls_type": tls_type,
                    "tls_record_len": record_len,
                    "description": desc,
                }
            )

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(by=["frame", "record_index"])
    return df


def aggregate_by_frame(df_records: pd.DataFrame) -> pd.DataFrame:
    """
    Cria uma visão por *frame*:
      - uma linha por frame
      - coluna com resumo dos registros TLS presentes naquele frame
    """
    if df_records.empty:
        return pd.DataFrame()

    # Agrupar por frame
    agg_rows = []
    for frame, group in df_records.groupby("frame"):
        time = group["time"].iloc[0]
        len_bytes = group["len_bytes"].iloc[0]
        src_port = group["src_port"].iloc[0]
        dst_port = group["dst_port"].iloc[0]

        # Resumo dos registros desse frame
        summaries = []
        for _, row in group.iterrows():
            part = row["tls_type"]
            if row["description"]:
                part += f" ({row['description']})"
            summaries.append(part)

        summary = " | ".join(summaries)

        agg_rows.append(
            {
                "frame": frame,
                "time": time,
                "len_bytes": len_bytes,
                "src_port": src_port,
                "dst_port": dst_port,
                "tls_summary": summary,
            }
        )

    df_frames = pd.DataFrame(agg_rows).sort_values(by="frame")
    return df_frames


def main():
    capture = load_tls_json("captura_tls.json")

    # 1) Uma linha por registro TLS
    df_records = extract_records(capture)
    print("\n===== REGISTROS TLS (uma linha por record) =====\n")
    if df_records.empty:
        print("Nenhum registro TLS encontrado.")
    else:
        print(df_records.to_string(index=False))
        df_records.to_csv("tls_records_parsed.csv", index=False)
        print("\nArquivo salvo: tls_records_parsed.csv")

    # 2) Uma linha por frame, com resumo
    df_frames = aggregate_by_frame(df_records)
    print("\n===== FRAMES TLS (uma linha por frame) =====\n")
    if df_frames.empty:
        print("Nenhum frame TLS agregado.")
    else:
        print(df_frames.to_string(index=False))
        df_frames.to_csv("tls_frames_parsed.csv", index=False)
        print("\nArquivo salvo: tls_frames_parsed.csv")


if __name__ == "__main__":
    main()

