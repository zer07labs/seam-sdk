package com.zer07labs.seam;

/**
 * The bootstrap file is missing, malformed, fails validation, or cannot be created. Always loud.
 *
 * <p>Named for parity with Python's {@code IdentityFileError} (seam-sdk#201); it is an unchecked
 * {@link RuntimeException}, not a {@link java.lang.Error}.
 */
public final class IdentityFileError extends RuntimeException {
  public IdentityFileError(String message) {
    super(message);
  }

  public IdentityFileError(String message, Throwable cause) {
    super(message, cause);
  }
}
