package lab.zgc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.instana.sdk.annotation.Span;
import com.instana.sdk.support.SpanSupport;
import jakarta.annotation.PostConstruct;
import java.io.ByteArrayOutputStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPOutputStream;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.stereotype.Component;

@Component
@ManagedResource(objectName="zgcmaster:type=Fixture", description="Bounded synthetic heap workload")
public class Fixture {
    public static final class Sample {
        public long id;
        public long timestamp;
        public double amount;
        public int quantity;
        public boolean active;
        public String label;
        public byte[] payload;
        public byte[] archive;
        public int[] measurements;
        public long[] times;
        public Sample next;
    }
    public static final class TraceEvent {
        public long sequence;
        public String traceId;
        public String spanId;
        public String source;
    }
    private final ObjectMapper json;
    private final AtomicLong requests = new AtomicLong();
    private final List<Sample> samples = new ArrayList<>();
    private final TraceEvent[] traces = new TraceEvent[32];
    private final Map<String, Sample> byName = new HashMap<>();
    private final Map<String, String> dictionary = new HashMap<>();
    private byte[] compressed;
    private boolean lastInstanaTrace;
    private List<Object> examples;
    private volatile long touched;
    private volatile byte[] churn;

    public Fixture(ObjectMapper json) { this.json = json; }

    @PostConstruct public void initialize() throws Exception {
        int count = Integer.parseInt(System.getenv().getOrDefault("FIXTURE_RECORDS", "256"));
        if (count < 8 || count > 4096) throw new IllegalArgumentException("FIXTURE_RECORDS must be 8..4096");
        var expected = new ArrayList<Map<String, Object>>();
        for (int i = 0; i < count; i++) {
            Sample s = new Sample();
            s.id = 10_000L + i;
            s.timestamp = 1_750_000_000_000L + i * 1000L;
            s.amount = i * 1.25 + 0.5;
            s.quantity = i * 7;
            s.active = (i % 2 == 0);
            s.label = "sample-" + i + "-Berlin-\u03a9";
            s.payload = new byte[4096];
            for (int j = 0; j < s.payload.length; j++) s.payload[j] = (byte) (j * 31 + i * 17);
            s.measurements = new int[] {i, -i, 123456789, Integer.MIN_VALUE, Integer.MAX_VALUE};
            s.times = new long[] {s.timestamp, Long.MIN_VALUE, Long.MAX_VALUE};
            samples.add(s);
            byName.put(s.label, s);
            expected.add(Map.of("id", s.id, "quantity", s.quantity, "amount", s.amount,
                    "active", s.active, "label", s.label, "payload_sha256", digest(s.payload),
                    "measurements", s.measurements, "times", s.times));
        }
        for (int i = 0; i < count; i++) samples.get(i).next = samples.get((i + 1) % count);
        for (int i = 0; i < 16; i++) dictionary.put("fixture-key-" + i, "fixture-value-" + i + "-\u03a9");
        var bytes = new ByteArrayOutputStream();
        try (var gzip = new GZIPOutputStream(bytes)) {
            gzip.write("zgcmaster: a binary payload recovered from a Java byte array\n".repeat(32).getBytes(StandardCharsets.UTF_8));
        }
        compressed = bytes.toByteArray();
        for (Sample sample : samples) sample.archive = compressed;
        for (int i = 0; i < traces.length; i++) recordTrace();
        Path out = Path.of("/tmp/fixture");
        Files.createDirectories(out);
        json.writerWithDefaultPrettyPrinter().writeValue(out.resolve("expected.json").toFile(),
                Map.of("samples", expected, "gzip_sha256", digest(compressed), "sample_count", count,
                        "dictionary", dictionary));
        examples = new ArrayList<Object>(List.of(this, samples.getFirst(), samples.getFirst().label,
                new byte[0], new int[0], new long[0], new double[0], new char[0], new boolean[0],
                new short[0], new float[0], new Object[0], traces, traces[0], samples, byName,
                byName.entrySet().iterator().next(), requests));
        json.writerWithDefaultPrettyPrinter().writeValue(out.resolve("layout.json").toFile(), Layout.describe(examples));
        LoggerFactory.getLogger(Fixture.class).info("Fixture ready: {} retained samples, JMX bean registered", count);
    }

    /** Resolve lazy ZGC references throughout the known fixture graph before capture. */
    public synchronized Map<String, Object> prepare() throws Exception {
        long checksum = 0;
        for (Sample sample : samples) {
            checksum += sample.id + sample.next.id + sample.label.hashCode();
            checksum += sample.archive[0];
            for (byte b : sample.payload) checksum += b;
            for (int n : sample.measurements) checksum += n;
            for (long n : sample.times) checksum += n;
        }
        for (TraceEvent trace : traces) checksum += trace.traceId.hashCode() + trace.source.hashCode();
        for (var entry : dictionary.entrySet()) checksum += entry.getKey().hashCode() + entry.getValue().hashCode();
        for (byte b : compressed) checksum += b;
        touched = checksum;
        json.writerWithDefaultPrettyPrinter().writeValue(Path.of("/tmp/fixture/layout.json").toFile(), Layout.describe(examples));
        return Map.of("touched", touched, "samples", samples.size());
    }

    /** Bounded pressure across several GC cycles; only this synthetic fixture is affected. */
    public Map<String, Object> gcCycles() throws Exception {
        var before = Layout.describe(examples);
        for (int cycle = 0; cycle < 4; cycle++) {
            for (int i = 0; i < 128; i++) { churn = new byte[1024 * 1024]; churn[0] = (byte)i; }
            System.gc();
        }
        churn = null;
        prepare();
        return Map.of("klass_layout_unchanged", before.equals(Layout.describe(examples)),
                "collections", ManagementFactory.getGarbageCollectorMXBeans().stream()
                    .map(b -> Map.of("name", b.getName(), "count", b.getCollectionCount())).toList());
    }

    @Span(type=Span.Type.ENTRY, value="zgcmaster.fixture.request")
    public synchronized Map<String, Object> recordTrace() {
        String trace = SpanSupport.traceId();
        String span = SpanSupport.spanId();
        boolean active = trace != null;
        if (!active) { trace = UUID.randomUUID().toString().replace("-", ""); span = trace.substring(16); }
        long n = requests.incrementAndGet();
        TraceEvent event = new TraceEvent();
        event.sequence = n; event.traceId = trace; event.spanId = span; event.source = active ? "instana" : "local";
        traces[(int) (n % traces.length)] = event;
        lastInstanaTrace = active;
        MDC.put("trace_id", trace); MDC.put("span_id", span); MDC.put("trace_source", event.source);
        try {
            SpanSupport.annotate("fixture.sequence", Long.toString(n));
            LoggerFactory.getLogger(Fixture.class).info("Synthetic request {}", n);
            return Map.of("sequence", n, "trace_id", trace, "span_id", span, "trace_source", event.source);
        } finally { MDC.remove("trace_id"); MDC.remove("span_id"); MDC.remove("trace_source"); }
    }
    @ManagedAttribute public int getSampleCount() { return samples.size(); }
    @ManagedAttribute public long getRequestCount() { return requests.get(); }
    @ManagedAttribute public synchronized boolean isLastInstanaTrace() { return lastInstanaTrace; }
    public Map<String, Object> status() throws Exception {
        var server = ManagementFactory.getPlatformMBeanServer();
        var name = new javax.management.ObjectName("zgcmaster:type=Fixture");
        return Map.of("java", Runtime.version().toString(), "samples", samples.size(),
                "jmx_registered", server.isRegistered(name),
                "jmx_sample_count", server.getAttribute(name, "SampleCount"),
                "instana_trace_observed", isLastInstanaTrace(),
                "instana_agent_configured", System.getenv("INSTANA_AGENT_SHA256") != null,
                "collector", ManagementFactory.getGarbageCollectorMXBeans().stream().map(b -> b.getName()).toList());
    }
    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
