FROM maven:3.9.9-eclipse-temurin-21@sha256:3a4ab3276a087bf276f79cae96b1af04f53731bec53fb2e651aca79e4b10211e AS maven
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
