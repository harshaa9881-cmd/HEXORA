import concurrent.futures
import os

class ParallelEngine:
    """
    Splits file scanning workloads across multiple threads.
    Works with any language handler with a `.scan_file()` method.
    """

    def __init__(self, workers=8):
        self.workers = workers

    def run_parallel(self, file_list, callback):
        """
        callback(file_path) must return scan_result
        """

        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(callback, f): f for f in file_list}

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    results.append({
                        "error": str(e),
                        "file": futures[future]
                    })

        return results