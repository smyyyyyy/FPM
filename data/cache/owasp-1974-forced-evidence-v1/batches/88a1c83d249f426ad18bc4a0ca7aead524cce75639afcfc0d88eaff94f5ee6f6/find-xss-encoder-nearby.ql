import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00544.java" and targetLine = 73)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02495.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00147.java" and targetLine = 65)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02401.java" and targetLine = 52)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01176.java" and targetLine = 57)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02488.java" and targetLine = 52)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02589.java" and targetLine = 74)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00394.java" and targetLine = 62)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00546.java" and targetLine = 73)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02331.java" and targetLine = 63)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00151.java" and targetLine = 65)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00649.java" and targetLine = 51)
}

predicate inWindow(Element e) {
  exists(string targetFile, int targetLine |
    batchTarget(targetFile, targetLine) and
    (e.getLocation().getFile().getRelativePath() = targetFile and
  e.getLocation().getStartLine() <= targetLine + 30 and
  e.getLocation().getStartLine() >= targetLine - 80)
  )
}

predicate xssEncoder(MethodCall call) {
  call.getMethod().getName().regexpMatch("(?i)(encodeForHTML|encodeForHtml|escapeHtml|escapeHtml4|htmlEscape|escapeXml|encodeForJavaScript)")
}

from MethodCall call
where inWindow(call)
  and xssEncoder(call)
select call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine(), call, "XSS encoder/sanitizer call near alert: " + call.toString()
