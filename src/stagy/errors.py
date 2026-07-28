"""Exception hierarchy for Stagy. Everything raised by the library is a StagyError."""


class StagyError(Exception):
    """Base for all Stagy errors."""


class CapacityError(StagyError):
    """Payload does not fit in the cover with the given options."""


class IntegrityError(StagyError):
    """Container failed its CRC32 or a byte was corrupted."""


class WrongKeyError(StagyError):
    """Decryption failed — wrong passphrase or tampered ciphertext."""


class NoPayloadError(StagyError):
    """No Stagy container found in the cover (MAGIC missing)."""


class UnsupportedFormatError(StagyError):
    """Cover/output format is not supported by this codec."""
