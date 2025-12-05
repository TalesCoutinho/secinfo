#!/usr/bin/env python3
import pandas as pd
from scipy.stats import mannwhitneyu

def carregar_duracoes(path_csv: str):
    df = pd.read_csv(path_csv)
    dur = pd.to_numeric(df["duration_seconds"], errors="coerce").dropna()
    return dur

def main():

    plain = carregar_duracoes("metrics_plain.csv")
    tls   = carregar_duracoes("metrics_tls.csv")

    print(f"Amostras plain TCP: {len(plain)}")
    print(f"Amostras TLS:       {len(tls)}")

    stat, p = mannwhitneyu(plain, tls, alternative="two-sided")

    print("\n=== Teste Mann-Whitney U ===")
    print(f"Estatística U = {stat:.3f}")
    print(f"p-valor        = {p:.6g}")

    alpha = 0.05
    if p < alpha:
        print("\n❗ Diferença significativa entre as distribuições.")
    else:
        print("\n✔️ Não há evidência suficiente para afirmar diferença estatística.")


if __name__ == "__main__":
    main()

