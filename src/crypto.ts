/**
 * Hardened Industrial-Grade Security Authentication Module
 * Compliant with modern NIST / OWASP guidelines for 2026 Web Infrastructure
 */

const ITERATIONS = 600000; // Modern computational threshold targeting ~150-250ms isolation runtime

/**
 * Encodes a password into a self-describing modular cryptographic hash format string.
 * Format: pbkdf2_sha256$iterations$saltHex$hashHex
 */
export async function generatePasswordParametricBlock(pwd: string): Promise<string> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(pwd);

  // Generate 16 bytes (128 bits) of true cryptographically random noise
  const saltBuffer = new Uint8Array(16);
  crypto.getRandomValues(saltBuffer);

  const baseKey = await crypto.subtle.importKey(
    "raw",
    passwordBuffer,
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBuffer,
      iterations: ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    256
  );

  const hashHex = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, "0")).join("");
  const saltHex = Array.from(saltBuffer).map(b => b.toString(16).padStart(2, "0")).join("");

  return `pbkdf2_sha256$${ITERATIONS}$${saltHex}$${hashHex}`;
}

/**
 * Validates an incoming plain-text password against a stored modular string payload.
 */
export async function verifyPasswordAgainstBlock(pwd: string, storedBlock: string): Promise<boolean> {
  try {
    // Parse the self-describing modular components
    const parts = storedBlock.split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") {
      throw new Error("Unsupported or corrupt password block structure.");
    }

    const iterations = parseInt(parts[1], 10);
    const saltHex = parts[2];
    const targetHashHex = parts[3];

    // Defensive Hex Matching to eliminate the risky non-null assertion (!)
    const hexBytesMatch = saltHex.match(/.{1,2}/g);
    if (!hexBytesMatch) {
      throw new Error("Cryptographic salt payload corruption detected.");
    }

    const saltBuffer = new Uint8Array(hexBytesMatch.map(byte => parseInt(byte, 16)));
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(pwd);

    const baseKey = await crypto.subtle.importKey(
      "raw",
      passwordBuffer,
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"]
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBuffer,
        iterations: iterations, // Tracks changes dynamically if iteration count upgrades later
        hash: "SHA-256",
      },
      baseKey,
      256
    );

    const checkHashHex = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, "0")).join("");
    
    return checkHashHex === targetHashHex;
  } catch (error) {
    console.error("Crypto verification fault:", error);
    return false; 
  }
}
