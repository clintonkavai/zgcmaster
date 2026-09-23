FROM maven:3.9.9-eclipse-temurin-21@sha256:3a4ab3276a087bf276f79cae96b1af04f53731bec53fb2e651aca79e4b10211e AS maven
FROM eclipse-temurin:22.0.2_9-jdk-jammy@sha256:d8e6ba486df17bf758888d2b1b608133d1eedca8daf69d3fc6bf78d8be81e07e AS build
COPY --from=maven /usr/share/maven /opt/maven
WORKDIR /src
COPY fixture/pom.xml .
COPY fixture/src src
RUN --mount=type=cache,id=zgcmaster-maven,target=/root/.m2 /opt/maven/bin/mvn -B -ntp package

FROM eclipse-temurin:22.0.2_9-jdk-jammy@sha256:d8e6ba486df17bf758888d2b1b608133d1eedca8daf69d3fc6bf78d8be81e07e
WORKDIR /app
COPY --from=build /src/target/fixture-1.0.0.war /app/fixture.war
COPY --from=build /src/target/fixture-1.0.0-layout-agent.jar /app/layout-agent.jar
COPY docker/start-fixture.sh docker/capture.sh /app/
ENTRYPOINT ["bash", "/app/start-fixture.sh"]
