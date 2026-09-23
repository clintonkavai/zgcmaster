package lab.zgc;

import com.sun.management.HotSpotDiagnosticMXBean;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.ByteOrder;
import java.util.*;
import sun.misc.Unsafe;

/** Laboratory-only sidecar. Exports layouts and class identities, NEVER object values or addresses. */
public final class Layout {
    public static Map<String, Object> describe(List<Object> examples) throws Exception {
        var flags = ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class);
        for (String option : List.of("UseCompressedOops")) {
            if (!flags.getVMOption(option).getValue().equals("false")) throw new IllegalStateException("Unsupported " + option);
        }
        boolean narrow = flags.getVMOption("UseCompressedClassPointers").getValue().equals("true");
        boolean generational = flags.getVMOption("ZGenerational").getValue().equals("true");
        if (!flags.getVMOption("UseZGC").getValue().equals("true") || Runtime.version().feature() != 21
                || ByteOrder.nativeOrder() != ByteOrder.LITTLE_ENDIAN
                || !flags.getVMOption("ObjectAlignmentInBytes").getValue().equals("8")) {
            throw new IllegalStateException("Requires Java 21, ZGC, little endian, 8-byte alignment");
        }
        Field singleton = Unsafe.class.getDeclaredField("theUnsafe");
        singleton.setAccessible(true);
        Unsafe unsafe = (Unsafe) singleton.get(null);
        var types = new LinkedHashMap<String, Object>();
        for (Object example : examples) {
            Class<?> cls = example.getClass();
            var schema = new LinkedHashMap<String, Object>();
            schema.put("name", cls.getName());
            schema.put("klass", "0x" + Long.toUnsignedString(narrow ? Integer.toUnsignedLong(unsafe.getInt(example, 8L)) : unsafe.getLong(example, 8L), 16));
            schema.put("size", LayoutAgent.instrumentation.getObjectSize(example));
            if (cls.isArray()) {
                schema.put("kind", "array");
                schema.put("element", cls.getComponentType().isPrimitive() ? cls.getComponentType().getName() : "reference");
                schema.put("base", unsafe.arrayBaseOffset(cls));
                schema.put("scale", unsafe.arrayIndexScale(cls));
                schema.put("length_offset", narrow ? 12 : 16);
                schema.put("fields", List.of());
            } else {
                schema.put("kind", "instance");
                var fields = new ArrayList<Map<String, Object>>();
                for (Class<?> parent = cls; parent != Object.class; parent = parent.getSuperclass()) {
                    for (Field field : parent.getDeclaredFields()) {
                        if (Modifier.isStatic(field.getModifiers())) continue;
                        fields.add(Map.of("name", field.getName(), "offset", unsafe.objectFieldOffset(field),
                                "type", field.getType().isPrimitive() ? field.getType().getName() : "reference"));
                    }
                }
                fields.sort(Comparator.comparingLong(f -> ((Number) f.get("offset")).longValue()));
                schema.put("fields", fields);
            }
            types.put(cls.getName(), schema);
        }
        return Map.of("version", 1, "profile", "hotspot21-zgc-" + (generational ? "gen-" : "nongen-") + (narrow ? "compressedklass-" : "uncompressed-") + "le64",
                "java", Runtime.version().toString(), "architecture", System.getProperty("os.arch"),
                "classes", List.copyOf(types.values()));
    }
}
