package jwt

import play.api.libs.json._

case class JWTHeader(alg: Algorithm, otherParameters: scala.collection.Map[String, JsValue])

object JWTHeader {

  implicit val reads = new Reads[JWTHeader] {
    def reads(json: JsValue): JsResult[JWTHeader] = json match {
      case JsObject(fields) =>
        val algorithmResult = fields.get("alg").fold[JsResult[Algorithm]](JsError("alg field missing"))(Algorithm.reads.reads)
        algorithmResult.map { alg =>
          JWTHeader(alg, fields.filterKeys(_ != "alg"))
        }
      case other => JsError(s"Header was not a JSON object")
    }
  }

}

