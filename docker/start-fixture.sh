#!/usr/bin/env bash
set -euo pipefail
mkdir -p /tmp/fixture
printf '%s\n' "$$" > /tmp/fixture.pid
agent=()
if [[ -n "${INSTANA_AGENT_SHA256:-}" ]]; then
  printf '%s  %s\n' "$INSTANA_AGENT_SHA256" /opt/instana/agent.jar | sha256sum -c -
  agent=(-javaagent:/opt/instana/agent.jar)
fi
profile=(-XX:-ZGenerational -XX:-UseCompressedClassPointers)
case "${ZGCM_FIXTURE_PROFILE:-nongen-uncompressed}" in
  nongen-uncompressed) ;;
  gen-compressedklass) profile=(-XX:+ZGenerational -XX:+UseCompressedClassPointers) ;;
  *) printf 'Unknown ZGCM_FIXTURE_PROFILE\n' >&2; exit 1 ;;
esac
exec java -Xms128m -Xmx256m -XX:+UseZGC "${profile[@]}" \
  -XX:-UseCompressedOops -XX:ObjectAlignmentInBytes=8 \
  -XX:ActiveProcessorCount=2 -XX:MaxDirectMemorySize=32m \
  -XX:+EnableDynamicAgentLoading -Dcom.sun.management.jmxremote \
  -Xlog:gc:file=/tmp/fixture/gc.log:time,level,tags \
  -javaagent:/app/layout-agent.jar "${agent[@]}" -jar /app/fixture.war
