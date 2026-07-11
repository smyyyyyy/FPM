import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00130.java" and targetLine = 87)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01740.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02103.java" and targetLine = 63)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02663.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00450.java" and targetLine = 87)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01230.java" and targetLine = 53)
}

from MethodCall call, Expr arg
where exists(string targetFile, int targetLine |
  batchTarget(targetFile, targetLine) and
  (call.getLocation().getFile().getRelativePath() = targetFile
  and call.getLocation().getStartLine() = targetLine
  and call.getMethod().getName() = "getInstance"
  and arg = call.getArgument(0))
)
select call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine(), call, arg, "Crypto algorithm argument: " + arg.toString()
