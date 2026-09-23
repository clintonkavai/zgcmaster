package lab.zgc;

import java.lang.instrument.Instrumentation;

/** Fixture-only instrumentation: provides actual shallow sizes, not guessed sizes. */
public final class LayoutAgent {
    public static volatile Instrumentation instrumentation;
    public static void premain(String options, Instrumentation value) { instrumentation = value; }
}
