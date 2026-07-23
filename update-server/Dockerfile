# Multi-stage build for the WSO2 Integrator update server.
#
# The service reads published manifests from the filesystem at
# <dataDir>/api/v1/updates/<channel>/<platform>/<arch>/... with dataDir="data"
# resolved relative to the working directory (see store.bal). Choreo's Ballerina
# buildpack only ships the compiled JAR, so the data/ tree is absent at runtime
# and every manifest 404s. This Dockerfile bundles data/ next to the JAR so the
# server serves the committed manifest fixtures.

# ---- build stage: compile the Ballerina package to a self-contained JAR ----
FROM ballerina/ballerina:2201.13.4 AS build
WORKDIR /home/ballerina/update-server
COPY --chown=ballerina:ballerina . .
RUN bal build

# ---- runtime stage: JRE + the JAR + the manifest data tree ----
FROM eclipse-temurin:21-jre

# Choreo requires the container to run as a non-root user with a UID in
# [10000, 20000]. Create one and own the app directory.
RUN groupadd -g 10014 appgroup && useradd -u 10014 -g appgroup -m -s /usr/sbin/nologin appuser

WORKDIR /home/appuser/app
# data/ must sit next to the JAR because dataDir="data" is resolved relative to
# the working directory the process runs from.
COPY --from=build --chown=10014:10014 /home/ballerina/update-server/target/bin/update_server.jar ./update_server.jar
COPY --from=build --chown=10014:10014 /home/ballerina/update-server/data ./data

USER 10014
EXPOSE 9600
CMD ["java", "-jar", "update_server.jar"]
