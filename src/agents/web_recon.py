import logging
import re
import shutil
import subprocess
from typing import Dict, Any, List


class WebReconAgent:
    """
    Specialized agent responsible for web service enumeration,
    directory brute-forcing (Gobuster / ffuf), and web tech discovery.
    """

    def __init__(self, default_wordlist: str = "/usr/share/wordlists/dirb/common.txt"):
        self.default_wordlist = default_wordlist

    def execute_dir_fuzz(self, target_url: str, wordlist: str = None) -> Dict[str, Any]:
        """
        Runs Gobuster directory enumeration against a discovered web target.
        """
        wordlist_path = wordlist or self.default_wordlist
        gobuster_path = shutil.which("gobuster")

        if not gobuster_path:
            logging.warning("Gobuster binary not found in system PATH. Falling back to ffuf or mock.")
            return self._run_ffuf_fallback(target_url, wordlist_path)

        cmd = [
            gobuster_path, "dir",
            "-u", target_url,
            "-w", wordlist_path,
            "-x", "php,html,txt",
            "-a", "AgenticRecon/1.0",
            "-r",
            "--timeout","25s",
            "-k",
            "-q",
            "--no-error"
        ]

        logging.info(f"[*] WebReconAgent executing: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            discovered_paths = []

            # Match lines like: /images (Status: 301) [Size: 178]
            for line in result.stdout.splitlines():
                line_str = line.strip()
                if line_str and "(Status:" in line_str:
                    parts = line_str.split()
                    path = parts[0]
                    # Extract status code if available
                    status_match = re.search(r"\(Status:\s*(\d+)\)", line_str)
                    status_code = status_match.group(1) if status_match else "200"

                    discovered_paths.append({
                        "path": path,
                        "url": f"{target_url.rstrip('/')}{path.lstrip('/')}",
                        "status": status_code,
                        "raw_entry": line_str
                    })

            return {
                "status": "success",
                "tool": "gobuster",
                "target": target_url,
                "discovered_paths": discovered_paths
            }

        except subprocess.TimeoutExpired:
            logging.error(f"Gobuster execution timed out for {target_url}")
            return {"status": "error", "reason": "Timeout"}
        except Exception as e:
            logging.error(f"WebReconAgent error: {str(e)}")
            return {"status": "error", "reason": str(e)}

    def _run_ffuf_fallback(self, target_url: str, wordlist_path: str) -> Dict[str, Any]:
        ffuf_path = shutil.which("ffuf")
        if not ffuf_path:
            logging.error("Neither Gobuster nor ffuf binaries were found in PATH.")
            return {"status": "error", "reason": "No web fuzzing binary installed"}

        target = target_url.rstrip('/') + "/FUZZ"
        cmd = [
            ffuf_path,
            "-u", target,
            "-w", wordlist_path,
            "-H", "User-Agent: AgenticRecon/1.0",
            "-s"
        ]

        logging.info(f"[*] WebReconAgent executing ffuf: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            paths = [{"path": line.strip(), "url": f"{target_url.rstrip('/')}/{line.strip()}"}
                     for line in result.stdout.splitlines() if line.strip()]
            return {"status": "success", "tool": "ffuf", "target": target_url, "discovered_paths": paths}
        except Exception as e:
            return {"status": "error", "reason": str(e)}