# File: performance_analysis/AES_key_performance.py

import time
import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Tuple
import statistics
import psutil
import boto3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import matplotlib.pyplot as plt
import numpy as np

@dataclass
class AESConfiguration:
    """Configuration class for AES variants"""
    key_size: int  # in bits
    rounds: int
    block_size: int  # in bits

@dataclass
class PerformanceMetrics:
    """Class to store performance metrics"""
    encryption_time: float  # in milliseconds
    decryption_time: float  # in milliseconds
    throughput: float  # in MB/s
    memory_usage: float  # in MB
    cpu_usage: float  # in percentage

class AESPerformanceAnalyzer:
    """Class to analyze AES encryption performance"""
    
    def __init__(self, sample_sizes=None):
        self.logger = logging.getLogger(__name__)
        self.sample_sizes = sample_sizes or [1024, 10*1024, 100*1024]  # Default sizes in bytes
        
        # Define AES variants configurations
        self.aes_variants = {
            'AES-128': AESConfiguration(128, 10, 128),
            'AES-192': AESConfiguration(192, 12, 128),
            'AES-256': AESConfiguration(256, 14, 128)
        }

    def generate_test_data(self, size: int) -> str:
        """Generate test data of specified size"""
        return 'x' * size

    def measure_cpu_usage(self) -> float:
        """Measure CPU usage percentage"""
        return psutil.Process().cpu_percent()

    def measure_memory_usage(self) -> float:
        """Measure memory usage in MB"""
        return psutil.Process().memory_info().rss / (1024 * 1024)

    def measure_single_operation(self, variant: str, data: str) -> PerformanceMetrics:
        """Measure performance for a single encryption/decryption operation"""
        config = self.aes_variants[variant]
        key = get_random_bytes(config.key_size // 8)
        
        # Measure encryption
        start_cpu = self.measure_cpu_usage()
        start_time = time.perf_counter()
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        encryption_time = (time.perf_counter() - start_time) * 1000

        # Measure decryption
        start_time = time.perf_counter()
        cipher = AES.new(key, AES.MODE_GCM, nonce=cipher.nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        decryption_time = (time.perf_counter() - start_time) * 1000

        end_cpu = self.measure_cpu_usage()
        
        # Calculate metrics
        data_size = len(data)
        total_time = (encryption_time + decryption_time) / 1000  # Convert to seconds
        throughput = (data_size / (1024 * 1024)) / total_time if total_time > 0 else 0

        return PerformanceMetrics(
            encryption_time=encryption_time,
            decryption_time=decryption_time,
            throughput=throughput,
            memory_usage=self.measure_memory_usage(),
            cpu_usage=(end_cpu - start_cpu)
        )

    def run_benchmark(self, num_iterations: int = 100) -> Dict[str, Dict[str, Dict[str, float]]]:
        """Run comprehensive benchmark across all variants and sample sizes"""
        results = {}
        
        for variant in self.aes_variants.keys():
            self.logger.info(f"Benchmarking {variant}...")
            variant_results = {}
            
            for size in self.sample_sizes:
                size_metrics = []
                test_data = self.generate_test_data(size)
                
                for _ in range(num_iterations):
                    metrics = self.measure_single_operation(variant, test_data)
                    size_metrics.append(metrics)
                
                # Calculate averages
                variant_results[f"{size/1024}KB"] = {
                    "avg_encryption_time": statistics.mean([m.encryption_time for m in size_metrics]),
                    "avg_decryption_time": statistics.mean([m.decryption_time for m in size_metrics]),
                    "avg_throughput": statistics.mean([m.throughput for m in size_metrics]),
                    "avg_memory_usage": statistics.mean([m.memory_usage for m in size_metrics]),
                    "avg_cpu_usage": statistics.mean([m.cpu_usage for m in size_metrics]),
                    "std_dev_encryption": statistics.stdev([m.encryption_time for m in size_metrics]),
                    "std_dev_decryption": statistics.stdev([m.decryption_time for m in size_metrics])
                }
            
            results[variant] = variant_results
        
        return results

    def generate_performance_report(self, results: Dict) -> str:
        """Generate a detailed performance report"""
        report = []
        report.append("AES Performance Analysis Report")
        report.append("=" * 50 + "\n")

        for variant, sizes in results.items():
            report.append(f"\n{variant} Performance Metrics:")
            report.append("-" * 30)
            
            for size, metrics in sizes.items():
                report.append(f"\nData Size: {size}")
                report.append(f"Average Encryption Time: {metrics['avg_encryption_time']:.2f} ms")
                report.append(f"Average Decryption Time: {metrics['avg_decryption_time']:.2f} ms")
                report.append(f"Average Throughput: {metrics['avg_throughput']:.2f} MB/s")
                report.append(f"Average Memory Usage: {metrics['avg_memory_usage']:.2f} MB")
                report.append(f"Average CPU Usage: {metrics['avg_cpu_usage']:.2f}%")
                report.append(f"Std Dev (Encryption): {metrics['std_dev_encryption']:.2f} ms")
                report.append(f"Std Dev (Decryption): {metrics['std_dev_decryption']:.2f} ms")

        return "\n".join(report)

    def plot_performance_comparison(self, results: Dict, output_dir: str = "performance_plots"):
        """Generate performance comparison plots"""
        import os
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        metrics = ['avg_encryption_time', 'avg_decryption_time', 'avg_throughput', 'avg_cpu_usage']
        titles = ['Encryption Time', 'Decryption Time', 'Throughput', 'CPU Usage']
        ylabels = ['Time (ms)', 'Time (ms)', 'MB/s', 'CPU Usage (%)']

        for metric, title, ylabel in zip(metrics, titles, ylabels):
            plt.figure(figsize=(10, 6))
            x = np.arange(len(self.sample_sizes))
            width = 0.25
            
            for i, (variant, sizes) in enumerate(results.items()):
                values = [sizes[f"{size/1024}KB"][metric] for size in self.sample_sizes]
                plt.bar(x + i*width, values, width, label=variant)

            plt.xlabel('Data Size (KB)')
            plt.ylabel(ylabel)
            plt.title(f'{title} Comparison')
            plt.xticks(x + width, [f"{size/1024}KB" for size in self.sample_sizes])
            plt.legend()
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.savefig(f"{output_dir}/{metric}_comparison.png")
            plt.close()

def main():
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize analyzer with custom sample sizes if needed
    analyzer = AESPerformanceAnalyzer(sample_sizes=[1024, 10240, 102400])
    
    # Run benchmarks
    results = analyzer.run_benchmark(num_iterations=50)
    
    # Generate and save report
    report = analyzer.generate_performance_report(results)
    with open("performance_analysis/reports/AES_key_performance_report.txt", "w") as f:
        f.write(report)
    
    # Generate plots
    analyzer.plot_performance_comparison(results)
    
    logging.info("Performance analysis completed. Check performance_report.txt and performance_plots directory for results.")

if __name__ == "__main__":
    main()