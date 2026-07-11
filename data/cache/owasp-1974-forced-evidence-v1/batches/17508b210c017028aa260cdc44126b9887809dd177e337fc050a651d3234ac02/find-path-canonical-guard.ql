import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02110.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01409.java" and targetLine = 67)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00626.java" and targetLine = 66)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02568.java" and targetLine = 78)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02557.java" and targetLine = 82)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02462.java" and targetLine = 62)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02204.java" and targetLine = 64)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02468.java" and targetLine = 62)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02301.java" and targetLine = 72)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00132.java" and targetLine = 77)
}

predicate inWindow(Element e) {
  exists(string targetFile, int targetLine |
    batchTarget(targetFile, targetLine) and
    (e.getLocation().getFile().getRelativePath() = targetFile and
  e.getLocation().getStartLine() <= targetLine + 45 and
  e.getLocation().getStartLine() >= targetLine - 80)
  )
}

predicate pathGuard(MethodCall call) {
  call.getMethod().getName().regexpMatch("(?i)(getCanonicalPath|getCanonicalFile|normalize|startsWith|toRealPath|resolve)")
}

from MethodCall call
where inWindow(call)
  and pathGuard(call)
select call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine(), call, "Path validation/canonicalization evidence near alert: " + call.toString()
