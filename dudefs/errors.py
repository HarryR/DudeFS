# DudeFS error hierarchy (package root).
#
# One tree so a consumer can `except DudeFSError` to catch anything this package
# raises, or `except <module>.<ModuleError>` (e.g. codec.CodecError) for a
# single module, or a specific leaf for one failure. Per-module base errors are
# defined in their own modules subclassing DudeFSError; this file holds only the
# root (it imports nothing, so every module can depend on it without a cycle).


class DudeFSError(Exception):
    """Root of every error raised by DudeFS. `except DudeFSError` catches all of
    them; module bases (CodecError, CryptoError, ArtifactError, …) subclass it."""
