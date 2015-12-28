package jwt

import play.api.libs.json._

sealed abstract class Algorithm(val javaxCryptoName: String)

sealed trait HMAC extends Algorithm
sealed trait RSA extends Algorithm
sealed trait EDCSA extends Algorithm

object Algorithm {

  // See https://tools.ietf.org/html/rfc7518#section-3.1
  // and https://tools.ietf.org/html/rfc7518#appendix-A.1
  case object HS256 extends Algorithm("HmacSHA256") with HMAC
  case object HS384 extends Algorithm("HmacSHA384") with HMAC
  case object HS512 extends Algorithm("HmacSHA512") with RSA
  case object RS256 extends Algorithm("SHA256withRSA") with RSA
  case object RS384 extends Algorithm("SHA384withRSA") with RSA
  case object RS512 extends Algorithm("SHA512withRSA") with RSA
  case object ES256 extends Algorithm("SHA256withECDSA") with EDCSA
  case object ES384 extends Algorithm("SHA384withECDSA") with EDCSA
  case object ES512 extends Algorithm("SHA512withECDSA") with EDCSA
  case object PS256 extends Algorithm("SHA256withRSAandMGF1") with RSA
  case object PS384 extends Algorithm("SHA384withRSAandMGF1") with RSA
  case object PS512 extends Algorithm("SHA512withRSAandMGF1") with RSA
  case object None extends Algorithm("")

  implicit val reads = new Reads[Algorithm] {
    def reads(json: JsValue): JsResult[Algorithm] = json match {
      case JsString("HS256") => JsSuccess(HS256)
      case JsString("HS384") => JsSuccess(HS384)
      case JsString("HS512") => JsSuccess(HS512)
      case JsString("RS256") => JsSuccess(RS256)
      case JsString("RS384") => JsSuccess(RS384)
      case JsString("RS512") => JsSuccess(RS512)
      case JsString("ES256") => JsSuccess(ES256)
      case JsString("ES384") => JsSuccess(ES384)
      case JsString("ES512") => JsSuccess(ES512)
      case JsString("PS256") => JsSuccess(PS256)
      case JsString("PS384") => JsSuccess(PS384)
      case JsString("PS512") => JsSuccess(PS512)
      case JsString("none") => JsSuccess(None)
      case JsString(other) => JsError(s"Unsupported algorithm: $other")
      case _ => JsError("alg field was not a string")
    }
  }

}
