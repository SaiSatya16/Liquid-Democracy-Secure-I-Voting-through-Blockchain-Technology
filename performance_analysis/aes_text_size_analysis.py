# File: performance_analysis/aes_text_size_analysis.py

import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Dict, List, Tuple
import statistics
import base64

class AESTextSizeAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.key_sizes = {
            'AES-128': 16,
            'AES-192': 24,
            'AES-256': 32
        }
        self.text_sizes = [
            64,      # 64 bytes
            256,     # 256 bytes
            1024,    # 1KB
            4096     # 4KB
        ]

    def measure_text_sizes(self, key_size: int, text_size: int) -> Tuple[int, int]:
        key = get_random_bytes(key_size)
        plaintext = get_random_bytes(text_size)
        
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Include nonce and tag in ciphertext size calculation
        total_ciphertext_size = len(ciphertext) + len(cipher.nonce) + len(tag)
        
        return len(plaintext), total_ciphertext_size

    def run_analysis(self, num_iterations: int = 50) -> Dict:
        results = {}
        for variant, key_size in self.key_sizes.items():
            size_results = {}
            for size in self.text_sizes:
                plain_sizes = []
                cipher_sizes = []
                
                for _ in range(num_iterations):
                    plain_size, cipher_size = self.measure_text_sizes(key_size, size)
                    plain_sizes.append(plain_size)
                    cipher_sizes.append(cipher_size)
                
                size_results[size] = {
                    'avg_plain_size': statistics.mean(plain_sizes),
                    'avg_cipher_size': statistics.mean(cipher_sizes),
                    'overhead_percentage': ((statistics.mean(cipher_sizes) - size) / size) * 100
                }
            results[variant] = size_results
        return results

    # File: performance_analysis/aes_text_size_analysis.py (continued)

    def generate_report(self, results: Dict) -> str:
        report = ["AES Text Size Analysis Report", "=" * 50, ""]
        
        for variant, sizes in results.items():
            report.append(f"\n{variant} Analysis:")
            report.append("-" * 30)
            
            for size, metrics in sizes.items():
                report.append(f"\nOriginal Size: {size} bytes")
                report.append(f"Average Plaintext Size: {metrics['avg_plain_size']:.1f} bytes")
                report.append(f"Average Ciphertext Size: {metrics['avg_cipher_size']:.1f} bytes")
                report.append(f"Overhead Percentage: {metrics['overhead_percentage']:.2f}%")
        
        return "\n".join(report)

def main():
    logging.basicConfig(level=logging.INFO)
    analyzer = AESTextSizeAnalyzer()
    
    results = analyzer.run_analysis()
    
    # Generate report
    report = analyzer.generate_report(results)
    with open('performance_analysis/reports/text_size_analysis_report.txt', 'w') as f:
        f.write(report)
    
    # Print summary table
    print("\nText Size Analysis Summary:")
    print("-" * 80)
    print(f"{'Size':<10} {'Type':<12} {'AES-128':<15} {'AES-192':<15} {'AES-256':<15}")
    print("-" * 80)
    
    for size in analyzer.text_sizes:
        # Print plaintext size
        plain_sizes = [
            results[variant][size]['avg_plain_size']
            for variant in ['AES-128', 'AES-192', 'AES-256']
        ]
        print(f"{size:<10}{'Plain':<12} {plain_sizes[0]:<15.1f} {plain_sizes[1]:<15.1f} {plain_sizes[2]:<15.1f}")
        
        # Print ciphertext size
        cipher_sizes = [
            results[variant][size]['avg_cipher_size']
            for variant in ['AES-128', 'AES-192', 'AES-256']
        ]
        print(f"{'':<10}{'Cipher':<12} {cipher_sizes[0]:<15.1f} {cipher_sizes[1]:<15.1f} {cipher_sizes[2]:<15.1f}")
        print("-" * 80)

if __name__ == "__main__":
    main()