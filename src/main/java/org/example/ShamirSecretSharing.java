package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This class implements Shamir's (t,n) secret sharing.
 * 
 * Secrets are represented as BigInteger objects, shares as ShamirShare objects.
 * 
 * Randomness is taken from a {@link SecureRandom} object.
 * 
 * @see ShamirShare
 * @see BigInteger
 * @see SecureRandom
 * 
 * @author elmar
 * 
 */
public class ShamirSecretSharing {

	/**
	 * Creates a (t,n) Shamir secret sharing object for n shares with threshold
	 * t.
	 * 
	 * @param t
	 *            threshold: any subset of t <= i <= n shares can recover the
	 *            secret.
	 * @param n
	 *            number of shares to use. Needs to fulfill n >= 2.
	 */
	public ShamirSecretSharing(int t, int n) {
		assert (t >= 2);
		assert (n >= t);

		this.t = t;
		this.n = n;
		this.rng = new SecureRandom();

		// use p = 2^256 + 297
		this.p = BigInteger.ONE.shiftLeft(256).add(BigInteger.valueOf(297));
		assert (this.p.isProbablePrime(2));
	}

	/**
	 * Shares the secret into n parts.
	 * 
	 * @param secret
	 *            The secret to share.
	 * 
	 * @return An array of the n shares.
	 */
	public ShamirShare[] share(BigInteger secret) {
		ShamirShare[] shares = new ShamirShare[n];
		BigInteger[] coefficients = new BigInteger[t - 1];
		coefficients[0] = secret;
		for (int i = 1; i < t - 1; i++) {
			// a should be between 0 and p-1
			coefficients[i] = new BigInteger(p.bitLength(), rng).mod(p);
		}
		for (int i = 0; i < n; i++) {
			shares[i] = new ShamirShare(
					BigInteger.valueOf(i + 1),
					horner(BigInteger.valueOf(i + 1), coefficients).mod(p)
			);
		}
		return shares;
	}

	/**
	 * Evaluates the polynomial a[0] + a[1]*x + ... + a[t-1]*x^(t-1) modulo p at
	 * point x using Horner's rule.
	 * 
	 * @param x
	 *            point at which to evaluate the polynomial
	 * @param a
	 *            array of coefficients
	 * @return value of the polynomial at point x
	 */
	private BigInteger horner(BigInteger x, BigInteger[] a) {
		BigInteger result = a[0];
		for (int i = a.length - 1; i > 0; i--) {
			result = result.add(a[i].multiply(x.pow(i))).mod(p);
		}
		return result;
	}

	/**
	 * Recombines the given shares into the secret.
	 *
	 * @param shares
	 *            A set of at least t out of the n shares for this secret.
	 *
	 * @return The reconstructed secret.
	 */
	public BigInteger combine(ShamirShare[] shares) {
		int k = shares.length;
		assert (k >= t);
		assert (k <= n);
		BigInteger secret = BigInteger.ZERO;

		for (int i = 0; i < k; i++) {
			BigInteger yi = shares[i].s;
			BigInteger product = BigInteger.ONE;
			for (int j = 0; j < k; j++) {
				if (i == j) continue;
				BigInteger xj = shares[j].x;
				BigInteger xi = shares[i].x;

				product = product.multiply(
						xj.negate().multiply(xi.subtract(xj).modInverse(p))
				).mod(p);
			}
			secret = secret.add(yi.multiply(product)).mod(p);
		}

		return secret;
	}

	public int maxSecretLength() {
		return this.p.bitLength() / 8;
	}

	public int getT() {
		return t;
	}

	public int getN() {
		return n;
	}

	private int t;
	private int n;
	private SecureRandom rng;
	private BigInteger p;

}
