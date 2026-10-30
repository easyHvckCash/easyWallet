"""POC Generator Base Class - all POCs only need to implement this interface"""
from typing import Iterator, Optional, Tuple


class PocGenerator:
    """
    Each POC implements this base class, handling only core computation logic.
    IO/progress/rate-limiting/batch output is handled by main.py Runner.

    Subclasses must implement:
      - poc_id (property): unique identifier
      - poc_name (property): human-readable name
      - total_space (property): total search space size
      - generate(start_index): generator method
    """

    @property
    def poc_id(self) -> str:
        """Unique identifier, e.g. 'dice_no_floor'"""
        raise NotImplementedError

    @property
    def poc_name(self) -> str:
        """Human-readable name"""
        raise NotImplementedError

    @property
    def total_space(self) -> int:
        """Total search space size"""
        raise NotImplementedError

    @property
    def batch_size(self) -> int:
        """Number of mnemonics per output file (default 10000)"""
        return 10000

    def generate(self, start_index: int) -> Iterator[Tuple[int, Optional[str]]]:
        """
        Yield (current_index, mnemonic_or_none) starting from start_index.

        - current_index: the index currently being processed (for saving progress)
        - mnemonic_or_none: generated mnemonic, or None if index is invalid (skip)

        The caller collects non-None results and writes them to batch files.
        """
        raise NotImplementedError
