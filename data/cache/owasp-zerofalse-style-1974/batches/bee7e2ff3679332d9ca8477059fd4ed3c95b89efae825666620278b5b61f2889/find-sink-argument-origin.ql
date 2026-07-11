import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00933.java" and targetLine = 55)
}

from MethodCall call, Expr arg
where exists(string targetFile, int targetLine |
  batchTarget(targetFile, targetLine) and
  (call.getLocation().getFile().getRelativePath() = targetFile
  and call.getLocation().getStartLine() = targetLine
  and arg = call.getAnArgument())
)
select arg.getLocation().getFile().getRelativePath(), arg.getLocation().getStartLine(), arg, "Sink argument candidate: " + arg.toString()
