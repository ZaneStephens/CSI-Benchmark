import logging

def setup_logging():
    logging.basicConfig(
        filename='cis_benchmark_log.txt',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )