import unittest
from unittest.mock import patch, MagicMock
from src.agents.web_recon import WebReconAgent


class TestWebReconAgent(unittest.TestCase):

    def setUp(self):
        self.agent = WebReconAgent(default_wordlist="/usr/share/wordlists/dirb/common.txt")

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_execute_dir_fuzz_gobuster_success(self, mock_subproc, mock_which):
        # Mock binaries existence
        mock_which.side_effect = lambda bin_name: "/usr/bin/gobuster" if bin_name == "gobuster" else None

        # Mock CLI stdout from Gobuster
        mock_subproc.returncode = 0
        mock_subproc.return_value = MagicMock(
            stdout="/images (Status: 301)\n/shared (Status: 200)\n",
            returncode=0
        )

        res = self.agent.execute_dir_fuzz("http://scanme.nmap.org")

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["tool"], "gobuster")
        self.assertEqual(len(res["discovered_paths"]), 2)
        self.assertEqual(res["discovered_paths"][0]["path"], "/images")


if __name__ == "__main__":
    unittest.main()