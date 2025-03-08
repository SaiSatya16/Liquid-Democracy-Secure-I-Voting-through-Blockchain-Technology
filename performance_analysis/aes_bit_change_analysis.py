# File: performance_analysis/aes_bit_change_analysis.py

import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Dict, List
import statistics
import matplotlib.pyplot as plt
import numpy as np

class AESBitChangeAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.key_sizes = {
            'AES-128': 16,
            'AES-192': 24,
            'AES-256': 32
        }
        self.bit_changes = [10, 20, 30, 40, 50]  # Number of bits to change in key

    def count_different_bits(self, data1: bytes, data2: bytes) -> int:
        """Count the number of different bits between two byte sequences"""
        if len(data1) != len(data2):
            raise ValueError("Byte sequences must be of equal length")
            
        diff_bits = 0
        for b1, b2 in zip(data1, data2):
            xor = b1 ^ b2
            diff_bits += bin(xor).count('1')
        return diff_bits

    def modify_key_bits(self, key: bytes, num_bits: int) -> bytes:
        """Modify specific number of bits in the key"""
        key_list = bytearray(key)
        total_bits = len(key) * 8
        bits_to_flip = np.random.choice(total_bits, num_bits, replace=False)
        
        for bit_pos in bits_to_flip:
            byte_pos = bit_pos // 8
            bit_in_byte = bit_pos % 8
            key_list[byte_pos] ^= (1 << bit_in_byte)
        
        return bytes(key_list)

    def measure_bit_changes(self, key_size: int, num_key_bits_change: int, plaintext_size: int = 1024) -> float:
        """Measure percentage of bit changes in ciphertext when key bits are changed"""
        # Generate original key and plaintext
        key = get_random_bytes(key_size)
        plaintext = get_random_bytes(plaintext_size)
        
        # Get original ciphertext
        cipher1 = AES.new(key, AES.MODE_GCM)
        ciphertext1, tag1 = cipher1.encrypt_and_digest(plaintext)
        
        # Modify key and get new ciphertext
        modified_key = self.modify_key_bits(key, num_key_bits_change)
        cipher2 = AES.new(modified_key, AES.MODE_GCM)
        ciphertext2, tag2 = cipher2.encrypt_and_digest(plaintext)
        
        # Calculate percentage of different bits
        total_bits = len(ciphertext1) * 8
        diff_bits = self.count_different_bits(ciphertext1, ciphertext2)
        return (diff_bits / total_bits) * 100

    def run_analysis(self, num_iterations: int = 50) -> Dict:
        results = {}
        for variant, key_size in self.key_sizes.items():
            bit_change_results = {}
            for num_bits in self.bit_changes:
                percentages = []
                for _ in range(num_iterations):
                    pct_change = self.measure_bit_changes(key_size, num_bits)
                    percentages.append(pct_change)
                
                bit_change_results[num_bits] = {
                    'avg_change_percentage': statistics.mean(percentages),
                    'std_dev': statistics.stdev(percentages)
                }
            results[variant] = bit_change_results
        return results

    def generate_report(self, results: Dict) -> str:
        report = ["AES Bit Change Analysis Report", "=" * 50, ""]
        
        for variant, changes in results.items():
            report.append(f"\n{variant} Analysis:")
            report.append("-" * 30)
            
            for num_bits, metrics in changes.items():
                report.append(f"\nBits Changed in Key: {num_bits}")
                report.append(f"Average Bit Change in Ciphertext: {metrics['avg_change_percentage']:.2f}%")
                report.append(f"Standard Deviation: {metrics['std_dev']:.2f}%")
        
        return "\n".join(report)

    def plot_results(self, results: Dict, output_path: str):
        plt.figure(figsize=(10, 6))
        
        for variant, changes in results.items():
            x_values = list(changes.keys())
            y_values = [metrics['avg_change_percentage'] for metrics in changes.values()]
            plt.plot(x_values, y_values, marker='o', label=variant)

        plt.xlabel('Number of Bits Changed in Key')
        plt.ylabel('Percentage of Bits Changed in Ciphertext')
        plt.title('Avalanche Effect Analysis')
        plt.legend()
        plt.grid(True)
        plt.savefig(output_path)
        plt.close()

def main():
    logging.basicConfig(level=logging.INFO)
    analyzer = AESBitChangeAnalyzer()
    
    results = analyzer.run_analysis()
    
    # Generate report
    report = analyzer.generate_report(results)
    with open('performance_analysis/reports/bit_change_analysis_report.txt', 'w') as f:
        f.write(report)
    
    # Generate plot
    analyzer.plot_results(results, 'performance_analysis/plots/bit_change_analysis.png')
    
    # Print summary table
    print("\nBit Change Analysis Summary (% of bits changed in ciphertext):")
    print("-" * 70)
    print(f"{'Bits Changed':<15} {'AES-128':<15} {'AES-192':<15} {'AES-256':<15}")
    print("-" * 70)
    
    for bits in analyzer.bit_changes:
        changes = [
            results[variant][bits]['avg_change_percentage']
            for variant in ['AES-128', 'AES-192', 'AES-256']
        ]
        print(f"{bits:<15} {changes[0]:<15.2f} {changes[1]:<15.2f} {changes[2]:<15.2f}")

if __name__ == "__main__":
    main()