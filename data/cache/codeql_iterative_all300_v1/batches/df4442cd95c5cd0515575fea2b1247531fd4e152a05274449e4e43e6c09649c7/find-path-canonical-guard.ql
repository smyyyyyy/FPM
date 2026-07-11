import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java" and targetLine = 73)
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
