import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00805.java" and targetLine = 48)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01771.java" and targetLine = 50)
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
