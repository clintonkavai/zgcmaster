FROM maven:3.9.15-eclipse-temurin-26@sha256:029a8e2838ae68238ffb8be407cddbb3f07d4d839c60c6f26c619a69fd184531 AS maven
FROM eclipse-temurin:21.0.11_10-jdk-jammy@sha256:dbfd085220ae632a0830166e443747d1ee89e9038d92e3b48c3e5e9d8292b9a7 AS build
COPY --from=maven /usr/share/maven /opt/maven
WORKDIR /src
COPY fixture/pom.xml .
COPY fixture/src src
RUN --mount=type=cache,id=zgcmaster-maven,target=/root/.m2 /opt/maven/bin/mvn -B -ntp package

FROM eclipse-temurin:21.0.11_10-jdk-jammy@sha256:dbfd085220ae632a0830166e443747d1ee89e9038d92e3b48c3e5e9d8292b9a7
WORKDIR /app
COPY --from=build /src/target/fixture-1.0.0.war /app/fixture.war
COPY --from=build /src/target/fixture-1.0.0-layout-agent.jar /app/layout-agent.jar
COPY docker/start-fixture.sh docker/capture.sh /app/
ENTRYPOINT ["bash", "/app/start-fixture.sh"]
