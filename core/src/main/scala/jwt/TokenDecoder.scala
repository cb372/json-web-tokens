package jwt

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import org.apache.commons.codec.binary.Base64
import play.api.data.validation.ValidationError
import play.api.libs.json.{ Reads, JsPath, Json }

import scala.util.{ Failure, Success, Try }

object TokenDecoder {

  /**
   * Decode a JWS and verify its signature, returning either the token payload or an error.
   *
   * The payload will be deserialized from JSON to the type [[P]].
   * There must be a [[play.api.libs.json.Reads]] typeclass instance for [[P]] in implicit scope.
   * If you don't want to bother with a custom payload class, just use [[play.api.libs.json.JsObject]] for [[P]].
   *
   * @param token a JWT token in JWS Compact Serialization format: base64(header).base64(payload).base64(sig)
   * @param keys a collection of keys to use for verifying signatures
   * @tparam P the type of the payload
   * @return the deserialized payload or an error
   */
  def decodeAndVerify[P: Reads](token: String, keys: Keys): Either[DecodingError, P] = {
    for {
      encodedToken <- splitOnDots(token).right
      header <- decodeHeader(encodedToken.headerBase64).right
      payload <- decodePayload(encodedToken.payloadBase64).right
      _ <- verifySignature(header.alg, keys, encodedToken.headerBase64, encodedToken.payloadBase64, encodedToken.sigBase64).right
      // TODO verify expiry, issuer, audience, etc. if necessary
    } yield payload
  }

  private def splitOnDots(token: String): Either[DecodingError, EncodedToken] = {
    val parts = token.split('.')
    if (parts.length != 3)
      Left(InvalidTokenFormat)
    else
      Right(EncodedToken(parts(0), parts(1), parts(2)))
  }

  private def decodeHeader(string: String): Either[DecodingError, JWTHeader] = {
    val decoded = Base64.decodeBase64(string)
    Try(Json.parse(decoded)) match {
      case Success(jsValue) =>
        jsValue.validate[JWTHeader].asEither.left.map(errors => InvalidHeader(collectErrorMessages(errors)))
      case Failure(e) =>
        Left(InvalidHeader(Seq("Header was not valid json")))
    }
  }

  private def decodePayload[P: Reads](string: String): Either[DecodingError, P] = {
    val decoded = Base64.decodeBase64(string)
    Try(Json.parse(decoded)) match {
      case Success(jsValue) =>
        jsValue.validate[P].asEither.left.map(errors => InvalidPayload(collectErrorMessages(errors)))
      case Failure(_) =>
        Left(InvalidHeader(Seq("Payload was not valid json")))
    }
  }

  private def verifySignature(
    alg: Algorithm,
    keys: Keys,
    headerBase64: String,
    payloadBase64: String,
    sigBase64: String): Either[DecodingError, Unit] = alg match {
    case _: HMAC => verifyHMAC(alg, keys, headerBase64, payloadBase64, sigBase64)
    case _: RSA => verifyRSA(alg, keys, headerBase64, payloadBase64, sigBase64)
    // TODO EDCSA
    case Algorithm.None =>
      // Do nothing
      Right(())
  }

  private def verifyHMAC(
    alg: Algorithm,
    keys: Keys,
    headerBase64: String,
    payloadBase64: String,
    sigBase64: String): Either[DecodingError, Unit] = {
    keys.hmacSecret.fold[Either[DecodingError, Unit]](Left(NoKeyConfigured(alg))) { keyBytes =>
      val hmac = Mac.getInstance(alg.javaxCryptoName)
      hmac.init(new SecretKeySpec(keyBytes, alg.javaxCryptoName))
      val expectedSig = hmac.doFinal(s"$headerBase64.$payloadBase64".getBytes(StandardCharsets.US_ASCII))
      val suppliedSig = Base64.decodeBase64(sigBase64)

      if (MessageDigest.isEqual(suppliedSig, expectedSig))
        Right(())
      else
        Left(IncorrectSignature)
    }
  }

  private def verifyRSA(
    alg: Algorithm,
    keys: Keys,
    headerBase64: String,
    payloadBase64: String,
    sigBase64: String): Either[DecodingError, Unit] = {
    keys.rsaPublicKey.fold[Either[DecodingError, Unit]](Left(NoKeyConfigured(alg))) { publicKey =>
      val signature = java.security.Signature.getInstance(alg.javaxCryptoName)
      signature.initVerify(publicKey)
      signature.update(s"$headerBase64.$payloadBase64".getBytes(StandardCharsets.US_ASCII))

      if (signature.verify(Base64.decodeBase64(sigBase64)))
        Right(())
      else
        Left(IncorrectSignature)
    }
  }

  private def collectErrorMessages(errors: Seq[(JsPath, Seq[ValidationError])]) = errors.flatMap(_._2).map(_.message)

  private case class EncodedToken(headerBase64: String, payloadBase64: String, sigBase64: String)

}
