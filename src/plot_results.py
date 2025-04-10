#!/usr/bin/env python3
# plot_results.py - Generate boxplots for each metric from the CSV results.

import pandas as pd
import matplotlib.pyplot as plt

# Load results
df = pd.read_csv("experiment_results.csv")

# For each metric, create a boxplot grouped by Scenario
metrics = ["Throughput_Mbps", "Avg_Latency_ms", "Jitter_ms", "CPU_Usage_percent"]
ylabels = {
    "Throughput_Mbps": "Throughput (Mbps)",
    "Avg_Latency_ms": "Average Latency (ms)",
    "Jitter_ms": "Jitter (ms)",
    "CPU_Usage_percent": "CPU Usage (%)"
}
for metric in metrics:
    plt.figure(figsize=(6,4))
    # Create boxplot
    df.boxplot(column=metric, by="Scenario", grid=False)
    plt.title(f"{metric} by Scenario")
    plt.suptitle("")  # Remove default suptitle
    plt.xlabel("Scenario")
    plt.ylabel(ylabels.get(metric, metric))
    plt.xticks(rotation=45)
    plt.tight_layout()
    # Save plot to file
    plt.savefig(f"{metric}_boxplot.png")
    plt.close()
print("Boxplot graphs saved as PNG files for each metric.")
