import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02085.java" and targetLine = 56)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01207.java" and targetLine = 56)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00993.java" and targetLine = 69)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01146.java" and targetLine = 64)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01873.java" and targetLine = 69)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02168.java" and targetLine = 49)
}

from IfStmt guard
where exists(string targetFile, int targetLine |
  batchTarget(targetFile, targetLine) and
  (guard.getLocation().getFile().getRelativePath() = targetFile
  and guard.getLocation().getStartLine() <= targetLine + 20
  and guard.getLocation().getStartLine() >= targetLine - 20)
)
select guard.getLocation().getFile().getRelativePath(), guard.getLocation().getStartLine(), guard, "Guard condition near alert path: " + guard.getCondition().toString()
