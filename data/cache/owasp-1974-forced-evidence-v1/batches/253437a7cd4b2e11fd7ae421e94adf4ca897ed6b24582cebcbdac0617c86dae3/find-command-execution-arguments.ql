import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02253.java" and targetLine = 75)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01068.java" and targetLine = 64)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00980.java" and targetLine = 77)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01445.java" and targetLine = 70)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01937.java" and targetLine = 62)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00742.java" and targetLine = 67)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01791.java" and targetLine = 58)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00310.java" and targetLine = 85)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00827.java" and targetLine = 88)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02341.java" and targetLine = 71)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01600.java" and targetLine = 64)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00741.java" and targetLine = 70)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00090.java" and targetLine = 82)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02069.java" and targetLine = 65)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01182.java" and targetLine = 67)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01528.java" and targetLine = 59)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01444.java" and targetLine = 70)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01353.java" and targetLine = 66)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01865.java" and targetLine = 78)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01443.java" and targetLine = 72)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01607.java" and targetLine = 71)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00657.java" and targetLine = 65)
}

predicate inWindow(Element e) {
  exists(string targetFile, int targetLine |
    batchTarget(targetFile, targetLine) and
    (e.getLocation().getFile().getRelativePath() = targetFile and
  e.getLocation().getStartLine() <= targetLine + 35 and
  e.getLocation().getStartLine() >= targetLine - 80)
  )
}

predicate commandCall(Call call) {
  exists(MethodCall methodCall |
    call = methodCall and
    methodCall.getMethod().getName().regexpMatch("(?i)(exec|start)")
  )
  or
  exists(ClassInstanceExpr ctor |
    call = ctor and
    ctor.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder")
  )
}

predicate constantStatus(Expr arg, string status) {
  arg.isCompileTimeConstant() and status = "yes"
  or
  not arg.isCompileTimeConstant() and status = "no"
}

from Call call, Expr arg, string status
where inWindow(call)
  and commandCall(call)
  and arg = call.getAnArgument()
  and constantStatus(arg, status)
select call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine(), call,
  "Command execution evidence: call=" + call.toString() +
  ", arg=" + arg.toString() +
  ", arg_compile_time_constant=" + status
