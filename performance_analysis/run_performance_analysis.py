# File: performance_analysis/run_performance_analysis.py

import os
import logging
import time
from datetime import datetime
from performance_analysis.aes_mode_analysis import AESModeAnalyzer
from performance_analysis.aes_payload_analysis import AESPayloadAnalyzer
from performance_analysis.aes_text_size_analysis import AESTextSizeAnalyzer
from performance_analysis.aes_bit_change_analysis import AESBitChangeAnalyzer
from performance_analysis.AES_key_performance import AESPerformanceAnalyzer
import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PerformanceAnalysisRunner:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.reports_dir = os.path.join(self.base_dir, 'reports')
        self.plots_dir = os.path.join(self.base_dir, 'plots')
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create directories
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.plots_dir, exist_ok=True)
        logger.info(f"Initialized directories: {self.reports_dir}, {self.plots_dir}")


    def run_key_performance_analysis(self):
        """Run AES key performance analysis"""
        logger.info("Starting AES Key Performance Analysis...")
        try:
            analyzer = AESPerformanceAnalyzer(sample_sizes=[1024, 10*1024, 100*1024])
            results = analyzer.run_benchmark(num_iterations=50)
            report = analyzer.generate_performance_report(results)
            self.save_report("key_performance_analysis", report)
            analyzer.plot_performance_comparison(results, output_dir=self.plots_dir)
            logger.info("Key Performance Analysis completed")
            return results
        except Exception as e:
            logger.error(f"Error in key performance analysis: {str(e)}")
            raise

    def run_mode_analysis(self):
        """Run AES mode analysis"""
        logger.info("Starting AES Mode Analysis...")
        try:
            analyzer = AESModeAnalyzer()
            results = analyzer.run_comprehensive_analysis()
            report = analyzer.generate_report(results)
            self.save_report("mode_analysis", report)
            logger.info("Mode Analysis completed")
            return results
        except Exception as e:
            logger.error(f"Error in mode analysis: {str(e)}")
            raise

    def run_payload_analysis(self):
        """Run AES payload analysis"""
        logger.info("Starting AES Payload Analysis...")
        try:
            analyzer = AESPayloadAnalyzer()
            results = analyzer.run_analysis()
            report = analyzer.generate_report(results)
            self.save_report("payload_analysis", report)
            plot_path = os.path.join(self.plots_dir, f'payload_performance_{self.timestamp}.png')
            analyzer.plot_results(results, plot_path)
            logger.info("Payload Analysis completed")
            return results
        except Exception as e:
            logger.error(f"Error in payload analysis: {str(e)}")
            raise

    def run_text_size_analysis(self):
        """Run AES text size analysis"""
        logger.info("Starting AES Text Size Analysis...")
        try:
            analyzer = AESTextSizeAnalyzer()
            results = analyzer.run_analysis()
            report = analyzer.generate_report(results)
            self.save_report("text_size_analysis", report)
            logger.info("Text Size Analysis completed")
            return results
        except Exception as e:
            logger.error(f"Error in text size analysis: {str(e)}")
            raise

    def run_bit_change_analysis(self):
        """Run AES bit change analysis"""
        logger.info("Starting AES Bit Change Analysis...")
        try:
            analyzer = AESBitChangeAnalyzer()
            results = analyzer.run_analysis()
            report = analyzer.generate_report(results)
            self.save_report("bit_change_analysis", report)
            plot_path = os.path.join(self.plots_dir, f'bit_change_analysis_{self.timestamp}.png')
            analyzer.plot_results(results, plot_path)
            logger.info("Bit Change Analysis completed")
            return results
        except Exception as e:
            logger.error(f"Error in bit change analysis: {str(e)}")
            raise

    def run_all_analyses(self):
        """Run all performance analyses"""
        total_start_time = time.time()
        results = {}
        
        try:
            # Run all analyses
            results['key'] = self.run_key_performance_analysis()
            results['mode'] = self.run_mode_analysis()
            results['payload'] = self.run_payload_analysis()
            results['text'] = self.run_text_size_analysis()
            results['bit'] = self.run_bit_change_analysis()

            # Generate consolidated report
            self.generate_consolidated_report(results)

            total_time = time.time() - total_start_time
            logger.info(f"All analyses completed in {total_time:.2f} seconds")
            
            # Print summary to console
            self.print_summary(results)

        except Exception as e:
            logger.error(f"Error during analysis suite: {str(e)}")
            raise

    def save_report(self, analysis_type: str, report: str):
        """Save individual analysis reports"""
        report_path = os.path.join(self.reports_dir, f'{analysis_type}_{self.timestamp}.txt')
        with open(report_path, 'w') as f:
            f.write(report)
        logger.info(f"Saved {analysis_type} report to {report_path}")

    def generate_consolidated_report(self, results: dict):
        """Generate a consolidated report of all analyses"""
        consolidated_report = [
            "AES Comprehensive Performance Analysis",
            "=" * 50,
            f"\nAnalysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "\nSummary of Results:",
        ]

        # Key Performance Summary
        consolidated_report.extend([
            "\n1. Key Performance Analysis:",
            "-" * 20
        ])
        for variant, sizes in results['key'].items():
            consolidated_report.append(f"\n{variant}:")
            for size, metrics in sizes.items():
                consolidated_report.append(
                    f"  {size}:"
                    f"\n    Encryption: {metrics['avg_encryption_time']:.3f} ms"
                    f"\n    Decryption: {metrics['avg_decryption_time']:.3f} ms"
                    f"\n    Throughput: {metrics['avg_throughput']:.2f} MB/s"
                )

        # Mode Analysis Summary
        consolidated_report.extend([
            "\n2. Mode Analysis:",
            "-" * 20
        ])
        for mode, variants in results['mode'].items():
            consolidated_report.append(f"\n{mode}:")
            for variant, metrics in variants.items():
                consolidated_report.append(
                    f"  {variant}: {metrics['avg_encryption_time']:.3f} ms"
                )

        # Payload Analysis Summary
        consolidated_report.extend([
            "\n3. Payload Analysis:",
            "-" * 20
        ])
        for variant, sizes in results['payload'].items():
            consolidated_report.append(f"\n{variant}:")
            for size, metrics in sizes.items():
                consolidated_report.append(
                    f"  {size/1024}KB: {metrics['avg_time']:.3f} ms"
                )

        # Text Size Analysis Summary
        consolidated_report.extend([
            "\n4. Text Size Analysis:",
            "-" * 20
        ])
        for variant, sizes in results['text'].items():
            consolidated_report.append(f"\n{variant}:")
            for size, metrics in sizes.items():
                consolidated_report.append(
                    f"  {size} bytes: {metrics['overhead_percentage']:.2f}% overhead"
                )

        # Bit Change Analysis Summary
        consolidated_report.extend([
            "\n5. Bit Change Analysis:",
            "-" * 20
        ])
        for variant, changes in results['bit'].items():
            consolidated_report.append(f"\n{variant}:")
            for bits, metrics in changes.items():
                consolidated_report.append(
                    f"  {bits} bits: {metrics['avg_change_percentage']:.2f}% change"
                )

        report_path = os.path.join(self.reports_dir, f'consolidated_report_{self.timestamp}.txt')
        with open(report_path, 'w') as f:
            f.write('\n'.join(consolidated_report))
        logger.info(f"Saved consolidated report to {report_path}")

    def print_summary(self, results: dict):
        """Print a summary of all analyses to console"""
        print("\n" + "=" * 60)
        print("AES Performance Analysis Summary")
        print("=" * 60)

        # Key Performance Summary
        print("\nKey Performance Analysis Summary:")
        print("-" * 60)
        print(f"{'Size':<10} {'Metric':<15} {'AES-128':<15} {'AES-192':<15} {'AES-256':<15}")
        print("-" * 60)
        
        metrics = ['avg_encryption_time', 'avg_decryption_time', 'avg_throughput']
        metric_names = ['Encryption', 'Decryption', 'Throughput']
        
        for size in list(results['key']['AES-128'].keys()):
            for metric, metric_name in zip(metrics, metric_names):
                print(f"{size:<10} {metric_name:<15}", end='')
                for variant in ['AES-128', 'AES-192', 'AES-256']:
                    print(f"{results['key'][variant][size][metric]:<15.3f}", end='')
                print()
            print("-" * 60)

        # Mode Analysis Summary
        print("\nMode Analysis Summary (Encryption Time in ms):")
        print("-" * 60)
        print(f"{'Mode':<10} {'AES-128':<15} {'AES-192':<15} {'AES-256':<15}")
        print("-" * 60)
        
        for mode in results['mode']:
            times = [results['mode'][mode][variant]['avg_encryption_time']
                    for variant in ['AES-128', 'AES-192', 'AES-256']]
            print(f"{mode:<10} {times[0]:<15.3f} {times[1]:<15.3f} {times[2]:<15.3f}")

def main():
    try:
        runner = PerformanceAnalysisRunner()
        runner.run_all_analyses()
    except Exception as e:
        logger.error(f"Performance analysis failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()