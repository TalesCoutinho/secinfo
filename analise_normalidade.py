#!/usr/bin/env python3
import pandas as pd
from scipy.stats import shapiro

def carregar_duracoes(path_csv: str):
    """
    Lê o CSV e retorna a série de tempos de duração (em segundos) como float.
    Ignora linhas com NaN.
    """
    df = pd.read_csv(path_csv)
    # Ajusta o nome da coluna se for diferente
    col = "duration_seconds"
    if col not in df.columns:
        raise ValueError(f"Coluna '{col}' não encontrada em {path_csv}. Colunas disponíveis: {df.columns}")
    duracoes = pd.to_numeric(df[col], errors="coerce").dropna()
    return duracoes


def testar_shapiro(duracoes, nome: str):
    """
    Roda o teste de Shapiro–Wilk e imprime interpretação básica.
    """
    print(f"\n=== Teste de Shapiro–Wilk: {nome} ===")
    stat, p = shapiro(duracoes)
    print(f"Estatística W = {stat:.6f}")
    print(f"p-valor       = {p:.6g}")

    alpha = 0.05
    if p > alpha:
        print(f"Com α = {alpha}, NÃO rejeitamos H0: os dados são compatíveis com normalidade.")
    else:
        print(f"Com α = {alpha}, rejeitamos H0: os dados NÃO parecem normais.")


def main():
    # caminhos dos arquivos de métricas
    csv_plain = "metrics_plain.csv"
    csv_tls = "metrics_tls.csv"

    # Carregar durações
    dur_plain = carregar_duracoes(csv_plain)
    dur_tls = carregar_duracoes(csv_tls)

    print(f"Total de amostras (plain TCP): {len(dur_plain)}")
    print(f"Total de amostras (TLS):        {len(dur_tls)}")

    # Rodar Shapiro–Wilk para cada distribuição
    testar_shapiro(dur_plain, "TCP sem TLS (plain)")
    testar_shapiro(dur_tls, "TCP com TLS")


if __name__ == "__main__":
    main()

