package jwt

import java.io.{ InputStream, InputStreamReader }
import java.security.{ PrivateKey, KeyFactory, PublicKey }
import java.security.spec.{ PKCS8EncodedKeySpec, X509EncodedKeySpec }

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.io.pem.PemReader

import scala.util.Try

/**
 * A collection of keys to use for signature verification.
 *
 * To verify a signature, you will need:
 *  - the symmetric key (a.k.a. the shared secret) if the token was signed using an HMAC algorithm such as HS256
 *  - the public key if the token was signed using an asymmetric key algorithm such as RS256
 *
 * The idea is that you pass all your keys to the [[TokenDecoder]],
 * and it chooses the appropriate key based on the `alg` parameter in the token header.
 */
case class Keys(
    private[jwt] val hmacSecret: Option[Array[Byte]] = None,
    private[jwt] val rsaPublicKey: Option[PublicKey] = None) {

  def withHmacSecret(secret: Array[Byte]): Keys = {
    val cleanSecret = copyByteArray(secret)
    copy(hmacSecret = Some(cleanSecret))
  }

  def withRSAPublicKey(publicKey: PublicKey): Keys =
    copy(rsaPublicKey = Some(publicKey))

  private def copyByteArray(bytes: Array[Byte]) = {
    val copy = new Array[Byte](bytes.length)
    System.arraycopy(bytes, 0, copy, 0, bytes.length)
    copy
  }

}

object Keys {

  private[this] val bouncyCastleProvider = new BouncyCastleProvider

  /**
   * Helper method for loading an RSA public key from the classpath.
   * Expects a public key in PEM format.
   *
   * To generate an RSA key in the appropriate format, use the following OpenSSL commands:
   *
   * ```
   * $ openssl genrsa -out private.pem 2048              # generates the private key
   * $ openssl rsa -in private.pem -pubout > public.pem  # generates the public key
   * ```
   */
  def loadRSAPublicKeyFromPemFileOnClasspath(path: String): Try[PublicKey] = {
    Try {
      val pemReader = new PemReader(new InputStreamReader(getClasspathResourceAsStream(path)))
      try {
        val keyBytes = pemReader.readPemObject().getContent
        val keySpec = new X509EncodedKeySpec(keyBytes)
        KeyFactory.getInstance("RSA", bouncyCastleProvider).generatePublic(keySpec)
      } finally {
        pemReader.close()
      }
    }
  }

  /**
   * Helper method for loading an RSA private key from the classpath.
   * Expects a private key in PEM format.
   *
   * To generate an RSA key in the appropriate format, use the following OpenSSL commands:
   *
   * ```
   * $ openssl genrsa -out private.pem 2048              # generates the private key
   * $ openssl rsa -in private.pem -pubout > public.pem  # generates the public key
   * ```
   */
  def loadRSAPrivateKeyFromPemFileOnClasspath(path: String): Try[PrivateKey] = {
    Try {
      val pemReader = new PemReader(new InputStreamReader(getClasspathResourceAsStream(path)))
      try {
        val keyBytes = pemReader.readPemObject().getContent
        val keySpec = new PKCS8EncodedKeySpec(keyBytes)
        KeyFactory.getInstance("RSA", bouncyCastleProvider).generatePrivate(keySpec)
      } finally {
        pemReader.close()
      }
    }
  }

  private def getClasspathResourceAsStream(path: String): InputStream = {
    val classloader = Option(Thread.currentThread().getContextClassLoader).getOrElse(classOf[Keys].getClassLoader)
    classloader.getResourceAsStream(path)
  }

}
