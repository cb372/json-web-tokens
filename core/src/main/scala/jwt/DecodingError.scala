package jwt

sealed trait DecodingError

case object InvalidTokenFormat extends DecodingError
case class InvalidHeader(messages: Seq[String]) extends DecodingError
case class InvalidPayload(messages: Seq[String]) extends DecodingError
case class NoKeyConfigured(alg: Algorithm) extends DecodingError
case object IncorrectSignature extends DecodingError

