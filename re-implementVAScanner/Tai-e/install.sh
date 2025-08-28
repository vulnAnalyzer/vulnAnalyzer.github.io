#!/bin/bash

 mvn install:install-file "-Dfile=Tai-e-plugin-1.0.jar" "-DgroupId=neu.lab" "-DartifactId=Tai-e-plugin" "-Dversion=1.0" "-Dpackaging=jar" "-DpomFile=Tai-e-plugin-1.0.pom"