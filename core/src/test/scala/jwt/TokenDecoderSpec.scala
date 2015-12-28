package jwt

import java.nio.charset.StandardCharsets

import jwt.Algorithm.HS256
import org.scalatest._
import play.api.libs.json.{ Json, JsBoolean, JsString, JsValue }

case class User(sub: String, name: String, admin: Boolean)

object User {
  implicit val reads = Json.reads[User]
}

class TokenDecoderSpec extends FlatSpec with Matchers with EitherValues {

  val hmacSecret = "secret".getBytes(StandardCharsets.UTF_8)
  val keys = Keys().withHmacSecret(hmacSecret)

  it should "accept a valid token" in {
    val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    val result = TokenDecoder.decodeAndVerify[Map[String, JsValue]](token, keys)
    result.right.value should be(Map(
      "sub" -> JsString("1234567890"),
      "name" -> JsString("John Doe"),
      "admin" -> JsBoolean(true)
    ))
  }

  it should "fail if it does not have a key for the algorithm specified in the header" in {
    val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    val result = TokenDecoder.decodeAndVerify[Map[String, JsValue]](token, Keys())
    result.left.value should be(NoKeyConfigured(HS256))
  }

  it should "deserialize a payload to a custom class" in {
    val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    val result = TokenDecoder.decodeAndVerify[User](token, keys)
    result.right.value should be(User("1234567890", "John Doe", true))
  }

  it should "reject a token that is not in the JMS 'header.payload.signature' format" in {
    val token = "wut"
    val result = TokenDecoder.decodeAndVerify[Map[String, JsValue]](token, keys)
    result.left.value should be(InvalidTokenFormat)
  }

  it should "reject a token whose header is invalid json" in {
    // header is missing the closing curly bracket
    val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCI=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    val result = TokenDecoder.decodeAndVerify[Map[String, JsValue]](token, keys)
    result.left.value shouldBe an[InvalidHeader]
  }

  it should "reject a token whose header does not specify the algorithm" in {
    // header is {"foo":"bar"}
    val token = "eyJmb28iOiJiYXIifQ==.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    val result = TokenDecoder.decodeAndVerify[Map[String, JsValue]](token, keys)
    result.left.value shouldBe an[InvalidHeader]
  }

  it should "reject a token whose payload cannot be deserialized" in {
    // payload is {"foo":"bar"}
    val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ==.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    val result = TokenDecoder.decodeAndVerify[User](token, keys)
    result.left.value shouldBe an[InvalidPayload]
  }

  it should "reject a JWS token with an incorrect signature" in {
    // signature is missing the last char
    val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7Hg"
    val result = TokenDecoder.decodeAndVerify[Map[String, JsValue]](token, keys)
    result.left.value should be(IncorrectSignature)
  }

  it should "decode an Unsecured JWS" in {
    val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    val result = TokenDecoder.decodeAndVerify[Map[String, JsValue]](token, keys)
    result.right.value should be(Map(
      "sub" -> JsString("1234567890"),
      "name" -> JsString("John Doe"),
      "admin" -> JsBoolean(true)
    ))
  }

  it should "decode a JWS with an RS256 signature" in {
    // Token was signed using the private key in src/test/resources/private.pem
    val publicKey = Keys.loadRSAPublicKeyFromPemFileOnClasspath("public.pem").getOrElse(fail("Failed to load RSA public key"))
    val keys = Keys().withRSAPublicKey(publicKey)
    val token =
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzb21lIjoicGF5bG9hZCJ9." +
        "OJIR0NhWWs9L0vECHy-qhyLdpeMwfqxpiYsEOFtPbwOaor4rkljGjGsIpR9TF9m6SEUyCIF95Xjc2-W-2Drc8LLCVStyMLC9XluzeVKsqRLhtvR4b23oP01Bo4y3qQlpWF5lmFkuj34N3I50fV_-MukEWYyM5CwVyW1rMdWO3-ACDsy6LLdGOdkwuVVeOP2MzC30k78fUskd9LfgEm85a2Sy2FrGf0aD2cKVXonEgi-H1HfBBTP75DV4ytQ2bQSlhs0V8OUFEWoOWpXa3yESettj3zGmO6Sl5Q0I6XIzXaoOz83xa4p98dxVIIK7Ez6PE9HgHIlyKHoBTHX9_garag"
    val result = TokenDecoder.decodeAndVerify[Map[String, JsValue]](token, keys)
    result.right.value should be(Map(
      "some" -> JsString("payload")
    ))
  }

}
