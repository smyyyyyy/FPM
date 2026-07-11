import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00825.java" and targetLine = 83)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02341.java" and targetLine = 71)
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
