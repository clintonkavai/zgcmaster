package lab.zgc;

import java.util.Map;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/fixture")
public class Controller {
    private final Fixture fixture;
    public Controller(Fixture fixture) { this.fixture = fixture; }
    @GetMapping("/status") public Map<String, Object> status() throws Exception { return fixture.status(); }
    @PostMapping("/request") public Map<String, Object> request() { return fixture.recordTrace(); }
    @PostMapping("/prepare") public Map<String, Object> prepare() throws Exception { return fixture.prepare(); }
    @PostMapping("/gc-cycles") public Map<String, Object> gcCycles() throws Exception { return fixture.gcCycles(); }
}
