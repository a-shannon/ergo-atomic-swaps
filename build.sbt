ThisBuild / scalaVersion := "2.13.16"
ThisBuild / organization := "io.github.a-shannon"
ThisBuild / version := "0.1.0"

lazy val root = (project in file("."))
  .settings(
    name := "ergo-atomic-swaps",
    libraryDependencies ++= Seq(
      "org.scorexfoundation" %% "sigma-state" % "6.0.3",
      "org.scalatest" %% "scalatest" % "3.2.20" % Test
    ),
    Test / parallelExecution := false,
    scalacOptions ++= Seq(
      "-deprecation",
      "-feature",
      "-unchecked",
      "-Xlint"
    )
  )
