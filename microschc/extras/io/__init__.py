# Check for pcapng availability
try:
    import pcapng
    has_pcapng = True
except ImportError:
    has_pcapng = False
    
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
    raise AttributeError(f"module 'microschc.extras.io' has no attribute '{name}'")