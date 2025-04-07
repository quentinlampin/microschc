"""Compatibility layer for Python version-specific features."""
import sys

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from backports.strenum import StrEnum

__all__ = ['StrEnum'] 