# File: performance_analysis/aes_mode_analysis.py

import time
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from dataclasses import dataclass
from typing import Dict, List
import statistics

@dataclass
class ModePerformanceMetrics:
    encryption_time: float
    decryption_time: float
    memory_usage: float

class AESModeAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.modes = {
            'ECB': AES.MODE_ECB,
            'CBC': AES.MODE_CBC,
            'CFB': AES.MODE_CFB,
            'CTR': AES.MODE_CTR,
            'GCM': AES.MODE_GCM
        }
        self.key_sizes = {
            'AES-128': 16,
            'AES-192': 24,
            'AES-256': 32
        }

    def measure_mode_performance(self, mode_name: str, key_size: int, data_size: int = 1024) -> ModePerformanceMetrics:
        key = get_random_bytes(key_size)
        data = get_random_bytes(data_size)
        mode = self.modes[mode_name]
        
        # Initialize cipher based on mode
        if mode in [AES.MODE_CBC, AES.MODE_CFB]:
            iv = get_random_bytes(16)
            encryption_time = self._measure_encryption(mode, key, data, iv=iv)
            decryption_time = self._measure_decryption(mode, key, data, iv=iv)
        elif mode == AES.MODE_GCM:
            encryption_time = self._measure_gcm_encryption(key, data)
            decryption_time = self._measure_gcm_decryption(key, data)
        elif mode == AES.MODE_CTR:
            nonce = get_random_bytes(8)
            encryption_time = self._measure_encryption(mode, key, data, nonce=nonce)
            decryption_time = self._measure_decryption(mode, key, data, nonce=nonce)
        else:  # ECB
            encryption_time = self._measure_encryption(mode, key, data)
            decryption_time = self._measure_decryption(mode, key, data)

        return ModePerformanceMetrics(
            encryption_time=encryption_time,
            decryption_time=decryption_time,
            memory_usage=self._measure_memory_usage()
        )

    def _measure_encryption(self, mode, key, data, **kwargs):
        start_time = time.perf_counter()
        cipher = AES.new(key, mode, **kwargs)
        padded_data = pad(data, AES.block_size) if mode != AES.MODE_CTR else data
        cipher.encrypt(padded_data)
        return (time.perf_counter() - start_time) * 1000  # Convert to ms

    def _measure_decryption(self, mode, key, data, **kwargs):
        cipher = AES.new(key, mode, **kwargs)
        padded_data = pad(data, AES.block_size) if mode != AES.MODE_CTR else data
        ciphertext = cipher.encrypt(padded_data)
        
        start_time = time.perf_counter()
        cipher = AES.new(key, mode, **kwargs)
        cipher.decrypt(ciphertext)
        return (time.perf_counter() - start_time) * 1000

    def _measure_gcm_encryption(self, key, data):
        start_time = time.perf_counter()
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.encrypt_and_digest(data)
        return (time.perf_counter() - start_time) * 1000

    def _measure_gcm_decryption(self, key, data):
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce
        
        start_time = time.perf_counter()
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.decrypt_and_verify(ciphertext, tag)
        return (time.perf_counter() - start_time) * 1000

    def _measure_memory_usage(self) -> float:
        import psutil
        process = psutil.Process()
        return process.memory_info().rss / (1024 * 1024)  # Convert to MB

    def run_comprehensive_analysis(self, num_iterations: int = 100) -> Dict:
        results = {}
        for mode in self.modes.keys():
            mode_results = {}
            for variant, key_size in self.key_sizes.items():
                measurements = []
                for _ in range(num_iterations):
                    metrics = self.measure_mode_performance(mode, key_size)
                    measurements.append(metrics)
                
                mode_results[variant] = {
                    'avg_encryption_time': statistics.mean([m.encryption_time for m in measurements]),
                    'avg_decryption_time': statistics.mean([m.decryption_time for m in measurements]),
                    'std_dev_encryption': statistics.stdev([m.encryption_time for m in measurements]),
                    'avg_memory_usage': statistics.mean([m.memory_usage for m in measurements])
                }
            results[mode] = mode_results
        return results

    def generate_report(self, results: Dict) -> str:
        report = ["AES Mode Performance Analysis Report", "=" * 50, ""]
        
        for mode, variants in results.items():
            report.append(f"\n{mode} Mode Performance:")
            report.append("-" * 30)
            
            for variant, metrics in variants.items():
                report.append(f"\n{variant}:")
                report.append(f"Average Encryption Time: {metrics['avg_encryption_time']:.3f} ms")
                report.append(f"Average Decryption Time: {metrics['avg_decryption_time']:.3f} ms")
                report.append(f"Encryption Time Std Dev: {metrics['std_dev_encryption']:.3f} ms")
                report.append(f"Average Memory Usage: {metrics['avg_memory_usage']:.2f} MB")
        
        return "\n".join(report)

def main():
    logging.basicConfig(level=logging.INFO)
    analyzer = AESModeAnalyzer()
    
    results = analyzer.run_comprehensive_analysis()
    report = analyzer.generate_report(results)
    
    with open('performance_analysis/reports/mode_analysis_report.txt', 'w') as f:
        f.write(report)
    
    # Print summary table
    print("\nMode Performance Summary (Encryption Time in ms):")
    print("-" * 60)
    print(f"{'Mode':<10} {'AES-128':<15} {'AES-192':<15} {'AES-256':<15}")
    print("-" * 60)
    
    for mode in results:
        times = [
            results[mode][variant]['avg_encryption_time']
            for variant in ['AES-128', 'AES-192', 'AES-256']
        ]
        print(f"{mode:<10} {times[0]:<15.3f} {times[1]:<15.3f} {times[2]:<15.3f}")

if __name__ == "__main__":
    main()