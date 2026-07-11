import java
import semmle.code.java.dataflow.RangeAnalysis

predicate batchTarget(string targetFile, int targetLine) {
  (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02110.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01409.java" and targetLine = 67)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00626.java" and targetLine = 66)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02568.java" and targetLine = 78)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02557.java" and targetLine = 82)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02462.java" and targetLine = 62)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02204.java" and targetLine = 64)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02468.java" and targetLine = 62)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02301.java" and targetLine = 72)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00132.java" and targetLine = 77)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02253.java" and targetLine = 75)
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
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00544.java" and targetLine = 73)
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
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00933.java" and targetLine = 55)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01629.java" and targetLine = 55)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01212.java" and targetLine = 61)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01732.java" and targetLine = 77)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00929.java" and targetLine = 75)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00334.java" and targetLine = 83)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02652.java" and targetLine = 77)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00333.java" and targetLine = 65)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01717.java" and targetLine = 79)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00837.java" and targetLine = 85)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02267.java" and targetLine = 57)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02546.java" and targetLine = 55)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01810.java" and targetLine = 53)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00432.java" and targetLine = 62)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02729.java" and targetLine = 55)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01879.java" and targetLine = 75)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01961.java" and targetLine = 59)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02089.java" and targetLine = 62)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02265.java" and targetLine = 59)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00602.java" and targetLine = 77)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01719.java" and targetLine = 78)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00105.java" and targetLine = 78)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00927.java" and targetLine = 65)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00344.java" and targetLine = 65)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00200.java" and targetLine = 66)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02266.java" and targetLine = 59)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01819.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02176.java" and targetLine = 51)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01818.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01816.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02740.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00114.java" and targetLine = 78)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02175.java" and targetLine = 51)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01217.java" and targetLine = 60)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01010.java" and targetLine = 71)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01085.java" and targetLine = 56)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00925.java" and targetLine = 56)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02631.java" and targetLine = 77)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02734.java" and targetLine = 55)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00519.java" and targetLine = 63)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02636.java" and targetLine = 78)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02727.java" and targetLine = 55)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02728.java" and targetLine = 56)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01216.java" and targetLine = 60)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02280.java" and targetLine = 58)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00674.java" and targetLine = 78)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02736.java" and targetLine = 53)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02368.java" and targetLine = 67)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00926.java" and targetLine = 64)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00763.java" and targetLine = 75)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01814.java" and targetLine = 52)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00336.java" and targetLine = 66)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00928.java" and targetLine = 60)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02365.java" and targetLine = 67)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02283.java" and targetLine = 57)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01628.java" and targetLine = 55)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02093.java" and targetLine = 60)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02536.java" and targetLine = 53)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01815.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02271.java" and targetLine = 58)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01468.java" and targetLine = 66)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00190.java" and targetLine = 70)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00939.java" and targetLine = 73)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00514.java" and targetLine = 62)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01813.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01968.java" and targetLine = 56)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01817.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00517.java" and targetLine = 62)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02732.java" and targetLine = 53)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01305.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01315.java" and targetLine = 53)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01555.java" and targetLine = 56)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00773.java" and targetLine = 65)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01885.java" and targetLine = 73)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02733.java" and targetLine = 53)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00430.java" and targetLine = 60)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00844.java" and targetLine = 87)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01089.java" and targetLine = 58)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01303.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00605.java" and targetLine = 72)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02739.java" and targetLine = 54)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00440.java" and targetLine = 59)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00938.java" and targetLine = 61)
  or (targetFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00513.java" and targetLine = 63)
}

predicate inWindow(Element e) {
  exists(string targetFile, int targetLine |
    batchTarget(targetFile, targetLine) and
    (e.getLocation().getFile().getRelativePath() = targetFile and
  e.getLocation().getStartLine() <= targetLine + 120 and
  e.getLocation().getStartLine() >= targetLine - 100)
  )
}

predicate constantStatus(Expr value, string status) {
  value.isCompileTimeConstant() and status = "yes"
  or
  not value.isCompileTimeConstant() and status = "no"
}

predicate exactIntValue(Expr value, int exact) {
  bounded(value, any(ZeroBound upperZero), exact, true, _) and
  bounded(value, any(ZeroBound lowerZero), exact, false, _)
}

bindingset[condition, left, right]
predicate comparisonOutcome(BinaryExpr condition, int left, int right, string outcome) {
  condition instanceof GTExpr and
  (left > right and outcome = "true" or left <= right and outcome = "false")
  or
  condition instanceof GEExpr and
  (left >= right and outcome = "true" or left < right and outcome = "false")
  or
  condition instanceof LTExpr and
  (left < right and outcome = "true" or left >= right and outcome = "false")
  or
  condition instanceof LEExpr and
  (left <= right and outcome = "true" or left > right and outcome = "false")
  or
  condition instanceof EQExpr and
  (left = right and outcome = "true" or left != right and outcome = "false")
  or
  condition instanceof NEExpr and
  (left != right and outcome = "true" or left = right and outcome = "false")
}

predicate conditionEvaluation(IfStmt guard, string detail) {
  exists(BinaryExpr condition, int left, int right, string outcome |
    condition = guard.getCondition() and
    exactIntValue(condition.getLeftOperand(), left) and
    exactIntValue(condition.getRightOperand(), right) and
    comparisonOutcome(condition, left, right, outcome) and
    detail =
      ", condition_exact_values: left=" + left.toString() +
      ", operator='" + condition.getOp() + "'" +
      ", right=" + right.toString() +
      ", result=" + outcome
  )
  or
  not exists(BinaryExpr condition, int left, int right, string outcome |
    condition = guard.getCondition() and
    exactIntValue(condition.getLeftOperand(), left) and
    exactIntValue(condition.getRightOperand(), right) and
    comparisonOutcome(condition, left, right, outcome)
  ) and
  detail = ", condition_exact_values: unavailable"
}

predicate directConstantEvidence(Expr write, string message) {
  exists(LocalVariableDeclExpr decl, Expr value |
    write = decl and
    value = decl.getInit() and
    value.isCompileTimeConstant() and
    message = "direct constant local initialization: " + decl.getName() + " = " + value.toString()
  )
  or
  exists(AssignExpr assign, Expr value |
    write = assign and
    value = assign.getRhs() and
    value.isCompileTimeConstant() and
    message = "direct constant assignment: " + assign.getDest().toString() + " = " + value.toString()
  )
}

predicate derivedConstantEvidence(Expr write, string message) {
  exists(LocalVariableDeclExpr decl, MethodCall call, VarAccess arg, LocalVariableDeclExpr sourceDecl, Expr sourceValue |
    write = decl and
    call = decl.getInit() and
    arg = call.getAnArgument() and
    sourceDecl.getVariable() = arg.getVariable() and
    sourceValue = sourceDecl.getInit() and
    sourceValue.isCompileTimeConstant() and
    message =
      "derived-from-constant initialization: " + decl.getName() + " = " + call.toString() +
      "; argument " + arg.toString() + " initialized as " + sourceValue.toString()
  )
}

predicate branchAssignmentEvidence(Expr write, string message) {
  exists(IfStmt guard, AssignExpr assign, Expr value, string branch, string status, string detail |
    write = assign and
    inWindow(guard) and
    value = assign.getRhs() and
    constantStatus(value, status) and
    (
      branch = "then" and assign.getEnclosingStmt().getEnclosingStmt*() = guard.getThen()
      or
      branch = "else" and assign.getEnclosingStmt().getEnclosingStmt*() = guard.getElse()
    ) and
    conditionEvaluation(guard, detail) and
    message =
      "branch assignment: if (" + guard.getCondition().toString() + ") branch=" + branch +
      ", " + assign.getDest().toString() + " = " + value.toString() +
      ", value_compile_time_constant=" + status + detail
  )
}

from Expr write, string message
where inWindow(write)
  and (
    directConstantEvidence(write, message)
    or derivedConstantEvidence(write, message)
    or branchAssignmentEvidence(write, message)
  )
select write.getLocation().getFile().getRelativePath(), write.getLocation().getStartLine(), write, message
