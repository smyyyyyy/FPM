import java

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01820.java" and targetLine = 54)
}

predicate inWindow(Element e) {
  exists(string targetFile, int targetLine |
    batchTarget(targetFile, targetLine) and
    (e.getLocation().getFile().getRelativePath() = targetFile and
  e.getLocation().getStartLine() <= targetLine + 30 and
  e.getLocation().getStartLine() >= targetLine - 80)
  )
}

predicate sqlApi(MethodCall call) {
  call.getMethod().getName().regexpMatch("(?i)(prepareStatement|execute|executeQuery|executeUpdate|query|queryForList|update|batchUpdate|setString|setInt|setLong|setObject)")
}

predicate constantStatus(Expr arg, string status) {
  arg.isCompileTimeConstant() and status = "yes"
  or
  not arg.isCompileTimeConstant() and status = "no"
}

from MethodCall call, Expr arg, string status
where inWindow(call)
  and sqlApi(call)
  and arg = call.getAnArgument()
  and constantStatus(arg, status)
select call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine(), call,
  "SQL evidence: method=" + call.getMethod().getName() +
  ", arg=" + arg.toString() +
  ", arg_compile_time_constant=" + status
