import logging
import subprocess
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from src.scope import ScopeValidator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ToolWrapper")


class BaseTool(ABC):

  def __init__(self, name: str, scope_validator: ScopeValidator):
    self.name = name
    self.scope_validator = scope_validator

  def execute(self, target: str, extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
    """Base execution flow: Scope check -> Command Construction -> Execution -> Parsing."""
    if not self.scope_validator.is_target_in_scope(target):
      logger.warning(
          f"[{self.name}] Target '{target}' BLOCKED by Scope Validator!"
      )
      return {
          "status": "blocked",
          "error": f"Target '{target}' is out of scope.",
          "data": [],
      }

    cmd = self.build_command(target, extra_args or [])
    logger.info(f"[{self.name}] Executing command: {' '.join(cmd)}")

    try:
      result = subprocess.run(
          cmd,
          capture_output=True,
          text=True,
          timeout=300,  # 5-minute guardrail timeout
          check=False,
      )

      if result.returncode != 0:
        logger.error(f"[{self.name}] Execution error: {result.stderr.strip()}")
        return {
            "status": "error",
            "error": result.stderr.strip(),
            "data": [],
        }

      parsed_data = self.parse_output(result.stdout)
      return {"status": "success", "error": None, "data": parsed_data}

    except subprocess.TimeoutExpired:
      logger.error(f"[{self.name}] Command timed out.")
      return {"status": "timeout", "error": "Execution timed out", "data": []}
    except Exception as e:
      logger.error(f"[{self.name}] Unexpected error: {str(e)}")
      return {"status": "exception", "error": str(e), "data": []}

  @abstractmethod
  def build_command(self, target: str, extra_args: List[str]) -> List[str]:
    """Constructs the command array (e.g. ['subfinder', '-d', target, '-json'])"""
    pass

  @abstractmethod
  def parse_output(self, raw_output: str) -> Any:
    """Parses tool output into structured Python dictionaries/lists."""
    pass