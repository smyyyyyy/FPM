import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01771.java" and targetLine = 50)
}

from MethodCall call
where exists(string targetFile, int targetLine |
  batchTarget(targetFile, targetLine) and
  (call.getLocation().getFile().getRelativePath() = targetFile
  and call.getLocation().getStartLine() <= targetLine + 20
  and call.getLocation().getStartLine() >= targetLine - 20
  and call.getMethod().getName().regexpMatch("(?i).*(sanitize|escape|encode|validate|allow|canonical).*"))
)
select call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine(), call, "Sanitizer-like call near alert path for " + "CWE-079" + ": " + call.getMethod().getName()
