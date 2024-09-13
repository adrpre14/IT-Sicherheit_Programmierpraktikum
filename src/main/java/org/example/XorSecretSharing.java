/**
 * 
 */
package org.example;

import java.security.SecureRandom;
import java.util.Random;

/**
 * This class implements the simple XOR-based (n,n) secret sharing.
 * 
 * Secrets and shares are both represented as byte[] arrays.
 * 
 * Randomness is taken from a {@link java.security.SecureRandom} object.
 * 
 * @see SecureRandom
 * 
 * @author elmar
 * 
 */
public class XorSecretSharing {

	/**
	 * Creates a XOR secret sharing object for n shares
	 * 
	 * @param n
	 *            number of shares to use. Needs to fulfill n >= 2.
	 */
	public XorSecretSharing(int n) {
		assert (n >= 2);
		this.n = n;
		this.rng = new SecureRandom();
	}

	/**
	 * Shares the secret into n parts.
	 * 
	 * @param secret
	 *            The secret to share.
	 * 
	 * @return An array of the n shares.
	 */
	public byte[][] share(final byte[] secret) {
		int length = secret.length;
		byte[][] shares = new byte[n][length];
		for (int i = 0; i < n - 1; i++) {
			this.rng.nextBytes(shares[i]);
		}

		byte[] lastShare = secret.clone();
		for (int i = 0; i < n - 1; i++) {
			for (int j = 0; j < length; j++) {
				lastShare[j] = (byte) (lastShare[j] ^ shares[i][j]);
			}
		}
		shares[n - 1] = lastShare;

		return shares;
	}

	/**
	 * Recombines the given shares into the secret.
	 * 
	 * @param shares
	 *            The complete set of n shares for this secret.
	 * 
	 * @return The reconstructed secret.
	 */
	public byte[] combine(final byte[][] shares) {
		byte[] secret = shares[0].clone();
		int length = secret.length;
		for (int i = 1; i < shares.length; i++) {
			for (int j = 0; j < length; j++) {
				secret[j] = (byte) (secret[j] ^ shares[i][j]);
			}
		}
		return secret;
	}

	private int n;

	public int getN() {
		return n;
	}

	private Random rng;
}
