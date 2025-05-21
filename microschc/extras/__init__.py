"""Optional features dependent on extra dependencies.

This module provides access to optional functionality that requires
additional dependencies that are not installed by default. These features
are only available when microschc is installed with the 'extras' option:

    pip install microschc[extras]
"""

# Define what extras are available
__all__ = ['pcapng']

from microschc.extras.io import has_pcapng
    
# Create a lazy loader for pcapng functionality
def __getattr__(name):
    """Lazy load optional modules only when requested."""
    if name == 'pcapng':
        if has_pcapng:
            # Only import the module when requested
            from microschc.extras.io import pcapng
            return pcapng
        else:
            raise ImportError(
                "The 'pcapng' module is not available. "
                "Install microschc with extras: pip install 'microschc[extras]'"
            )
    raise AttributeError(f"module 'microschc.extras' has no attribute '{name}'")
