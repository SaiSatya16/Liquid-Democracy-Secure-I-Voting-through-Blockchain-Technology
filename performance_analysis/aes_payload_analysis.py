# File: performance_analysis/aes_payload_analysis.py

import time
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Dict, List
import statistics
import matplotlib.pyplot as plt

class AESPayloadAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.key_sizes = {
            'AES-128': 16,
            'AES-192': 24,
            'AES-256': 32
        }
        self.payload_sizes = [
            1024,      # 1KB
            10*1024,   # 10KB
            100*1024,  # 100KB
            1024*1024  # 1MB
        ]

    def measure_computation_time(self, key_size: int, data_size: int) -> float:
        key = get_random_bytes(key_size)
        data = get_random_bytes(data_size)
        
        start_time = time.perf_counter()
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.encrypt_and_digest(data)
        return (time.perf_counter() - start_time) * 1000  # Convert to ms

    def run_analysis(self, num_iterations: int = 50) -> Dict:
        results = {}
        for variant, key_size in self.key_sizes.items():
            payload_results = {}
            for size in self.payload_sizes:
                times = []
                for _ in range(num_iterations):
                    time_taken = self.measure_computation_time(key_size, size)
                    times.append(time_taken)
                
                payload_results[size] = {
                    'avg_time': statistics.mean(times),
                    'std_dev': statistics.stdev(times)
                }
            results[variant] = payload_results
        return results

    def generate_report(self, results: Dict) -> str:
        report = ["AES Payload Size Performance Analysis", "=" * 50, ""]
        
        for variant, sizes in results.items():
            report.append(f"\n{variant} Performance:")
            report.append("-" * 30)
            
            for size, metrics in sizes.items():
                size_kb = size / 1024
                report.append(f"\nPayload Size: {size_kb:.1f}KB")
                report.append(f"Average Computation Time: {metrics['avg_time']:.3f} ms")
                report.append(f"Standard Deviation: {metrics['std_dev']:.3f} ms")
        
        return "\n".join(report)

    def plot_results(self, results: Dict, output_path: str):
        plt.figure(figsize=(10, 6))
        
        for variant, sizes in results.items():
            x_values = [size/1024 for size in sizes.keys()]  # Convert to KB
            y_values = [metrics['avg_time'] for metrics in sizes.values()]
            plt.plot(x_values, y_values, marker='o', label=variant)

        plt.xlabel('Payload Size (KB)')
        plt.ylabel('Computation Time (ms)')
        plt.title('AES Performance vs Payload Size')
        plt.legend()
        plt.grid(True)
        plt.savefig(output_path)
        plt.close()

def main():
    logging.basicConfig(level=logging.INFO)
    analyzer = AESPayloadAnalyzer()
    
    results = analyzer.run_analysis()
    
    # Generate report
    report = analyzer.generate_report(results)
    with open('performance_analysis/reports/payload_analysis_report.txt', 'w') as f:
        f.write(report)
    
    # Generate plot
    analyzer.plot_results(results, 'performance_analysis/plots/payload_performance.png')
    
    # Print summary table
    print("\nPayload Size Performance Summary (Time in ms):")
    print("-" * 70)
    print(f"{'Size':<10} {'AES-128':<15} {'AES-192':<15} {'AES-256':<15}")
    print("-" * 70)
    
    for size in analyzer.payload_sizes:
        times = [
            results[variant][size]['avg_time']
            for variant in ['AES-128', 'AES-192', 'AES-256']
        ]
        print(f"{size/1024:<10.1f}KB {times[0]:<15.3f} {times[1]:<15.3f} {times[2]:<15.3f}")

if __name__ == "__main__":
    main()