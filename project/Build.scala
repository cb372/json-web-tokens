import sbt._
import Keys._
import com.typesafe.sbt.SbtScalariform.scalariformSettings

object JsonWebTokensBuild extends Build {

  val playVersion = "2.4.6"

  val commonSettings = Seq(
    scalaVersion := "2.11.7",
    organization := "com.github.cb372"
  )

  val core = Project(id = "core", base = file("core"))
    .settings(commonSettings)
    .settings(scalariformSettings)
    .settings(
      libraryDependencies ++= Seq(
        "com.typesafe.play" %% "play-json" % playVersion,
        "commons-codec" % "commons-codec" % "1.10",
        "org.bouncycastle" % "bcprov-jdk15on" % "1.53",
        "org.scalatest" %% "scalatest" % "2.2.5" % "test"
      )
    )

  val root = Project(id = "json-web-tokens", base = file("."))
    .settings(commonSettings)
    .settings(
      publishArtifact := false
    )
    .aggregate(core)
}
