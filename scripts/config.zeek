module FINGERPRINT;

export {
  # delimiter used to indicate different pieces of a fingerprint value
  option delimiter: string = "_";

  # nothing but BSD-3
  option JA4_enabled:    bool = T;

  # potentially restricted licensing, consult a lawyer
  option JA4S_enabled:   bool = T;
  option JA4L_enabled:   bool = F;
  option JA4X_enabled:   bool = F;
  option JA4H_enabled:   bool = F;
  option JA4SSH_enabled: bool = F;
}
