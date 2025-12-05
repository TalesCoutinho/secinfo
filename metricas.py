import pandas as pd

plain = pd.read_csv("metrics_plain.csv")["duration_seconds"]
tls   = pd.read_csv("metrics_tls.csv")["duration_seconds"]

print("TCP sem TLS:")
print("  Mediana:", plain.median())
print("  Média:", plain.mean())
print("  Desvio padrão:", plain.std())
print()

print("TLS:")
print("  Mediana:", tls.median())
print("  Média:", tls.mean())
print("  Desvio padrão:", tls.std())
print("Diferença percentual na mediana:",
      (tls.median() - plain.median()) / plain.median() * 100, "%")

