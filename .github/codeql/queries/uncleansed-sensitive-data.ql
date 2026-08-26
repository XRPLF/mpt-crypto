/**
 * @name Sensitive stack value may not be cleansed on all exit paths
 * @description Finds stack variables that are explicitly cleansed, plus
 *              stack variables copied from those values, and reports
 *              paths where a sensitive write can reach a function exit
 *              without an OPENSSL_cleanse barrier.
 *
 *              Authored by Trail of Bits as part of the TOB-RIPCTXR
 *              revision audit (June 5, 2026 final report, Appendix H,
 *              figure H.1). The rule surfaced TOB-RIPCTXR-6 (uncleansed
 *              `prev` nonce buffer in `generate_deterministic_nonces`);
 *              the underlying code fix landed in PR #74. This file
 *              preserves the rule in-repo so future regressions
 *              involving sensitive-data lifecycles can be flagged at
 *              review time.
 *
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id cpp/custom/uncleansed-sensitive-data
 * @tags security
 *       external/cwe/cwe-226
 */

import cpp
import semmle.code.cpp.controlflow.StackVariableReachability

predicate callNamed(FunctionCall call, string name) {
  exists(Function target |
    target = call.getTarget() and
    (
      target.getName() = name or
      target.hasGlobalName(name)
    )
  )
}

predicate exprMentionsStackVar(Expr expr, StackVariable v) {
  exists(VariableAccess access |
    expr.getAChild*() = access and
    access.getTarget() = v
  )
}

predicate trackedStackVar(StackVariable v) {
  v instanceof LocalVariable and
  not v.getUnspecifiedType() instanceof PointerType
}

predicate exprDesignatesStackVar(Expr expr, StackVariable v) {
  expr = v.getAnAccess()
  or
  expr.(AddressOfExpr).getOperand() = v.getAnAccess()
  or
  expr.(ArrayExpr).getArrayBase() = v.getAnAccess()
  or
  expr.(PointerAddExpr).getLeftOperand() = v.getAnAccess()
}

predicate callCleansesStackVar(FunctionCall call, StackVariable v) {
  callNamed(call, "OPENSSL_cleanse") and
  exprDesignatesStackVar(call.getArgument(0), v)
}

predicate directlyCleansed(StackVariable v) {
  trackedStackVar(v) and
  exists(FunctionCall call | callCleansesStackVar(call, v))
}

predicate copyCall(FunctionCall call) {
  callNamed(call, "memcpy") or
  callNamed(call, "memmove") or
  callNamed(call, "__builtin_memcpy") or
  callNamed(call, "__builtin_memmove") or
  callNamed(call, "__builtin___memcpy_chk") or
  callNamed(call, "__builtin___memmove_chk")
}

predicate copyFromTo(StackVariable src, StackVariable dst, ControlFlowNode node) {
  exists(FunctionCall call |
    node = call and
    copyCall(call) and
    exprDesignatesStackVar(call.getArgument(0), dst) and
    exprMentionsStackVar(call.getArgument(1), src)
  )
  or
  exists(Assignment assign |
    node = assign and
    exprDesignatesStackVar(assign.getLValue(), dst) and
    exprDesignatesStackVar(assign.getRValue(), src)
  )
}

predicate sensitiveStackVar(StackVariable v) {
  trackedStackVar(v) and
  directlyCleansed(v)
  or
  trackedStackVar(v) and
  exists(StackVariable src, ControlFlowNode node |
    sensitiveStackVar(src) and
    copyFromTo(src, v, node)
  )
}

/**
 * Output-producing helpers in mpt-crypto whose first argument receives
 * data derived from a sensitive scalar or pubkey. Mirrors the audit's
 * sink set; extend here when adding new sensitive-output APIs.
 */
predicate scalarHelper(FunctionCall call) {
  callNamed(call, "secp256k1_mpt_scalar_reduce32") or
  callNamed(call, "secp256k1_mpt_scalar_add") or
  callNamed(call, "secp256k1_mpt_scalar_mul") or
  callNamed(call, "secp256k1_mpt_scalar_negate") or
  callNamed(call, "secp256k1_mpt_scalar_inverse") or
  callNamed(call, "secp256k1_mpt_scalar_get_b32") or
  callNamed(call, "secp256k1_mpt_uint64_to_scalar") or
  callNamed(call, "secp256k1_ec_pubkey_create")
}

predicate firstArgumentOutput(FunctionCall call) {
  callNamed(call, "memcpy") or
  callNamed(call, "memmove") or
  callNamed(call, "__builtin_memcpy") or
  callNamed(call, "__builtin_memmove") or
  callNamed(call, "__builtin___memcpy_chk") or
  callNamed(call, "__builtin___memmove_chk") or
  callNamed(call, "memset") or
  callNamed(call, "__builtin_memset") or
  callNamed(call, "__builtin___memset_chk") or
  callNamed(call, "RAND_bytes") or
  callNamed(call, "RAND_priv_bytes") or
  scalarHelper(call) or
  callNamed(call, "secp256k1_ec_pubkey_serialize") or
  callNamed(call, "secp256k1_mpt_elgamal_encrypt") or
  callNamed(call, "secp256k1_mpt_elgamal_add") or
  callNamed(call, "secp256k1_mpt_elgamal_sub")
}

predicate outputArgument(FunctionCall call, int index) {
  index = 0 and firstArgumentOutput(call)
  or
  index = 1 and
  (
    callNamed(call, "EVP_DigestFinal_ex") or
    callNamed(call, "EVP_MAC_final")
  )
  or
  index = 2 and callNamed(call, "EVP_MAC_final")
}

predicate functionWritesStackVar(FunctionCall call, StackVariable v) {
  exists(int index |
    outputArgument(call, index) and
    exprDesignatesStackVar(call.getArgument(index), v)
  )
}

predicate assignmentWritesStackVar(Assignment assign, StackVariable v) {
  exprDesignatesStackVar(assign.getLValue(), v)
}

predicate writesStackVar(ControlFlowNode node, StackVariable v) {
  exists(FunctionCall call |
    node = call and
    functionWritesStackVar(call, v)
  )
  or
  exists(Assignment assign |
    node = assign and
    assignmentWritesStackVar(assign, v)
  )
}

predicate sensitiveSource(ControlFlowNode node, StackVariable v) {
  directlyCleansed(v) and
  writesStackVar(node, v)
  or
  exists(StackVariable src |
    sensitiveStackVar(src) and
    copyFromTo(src, v, node)
  )
}

class SensitiveStackCleanup extends StackVariableReachability {
  SensitiveStackCleanup() { this = "SensitiveStackCleanup" }

  override predicate isSource(ControlFlowNode node, StackVariable v) {
    sensitiveStackVar(v) and
    sensitiveSource(node, v)
  }

  override predicate isSink(ControlFlowNode node, StackVariable v) {
    exists(ReturnStmt ret |
      node = ret and
      ret.getEnclosingFunction() = v.getFunction()
    )
  }

  override predicate isBarrier(ControlFlowNode node, StackVariable v) {
    exists(FunctionCall call |
      node = call and
      callCleansesStackVar(call, v)
    )
  }
}

predicate missingCleanseOnReturn(ControlFlowNode source, StackVariable v, ReturnStmt ret) {
  exists(SensitiveStackCleanup cfg |
    cfg.reaches(source, v, ret) and
    ret.getEnclosingFunction() = v.getFunction()
  )
}

string reportMessage(ControlFlowNode source, StackVariable v, ReturnStmt ret) {
  missingCleanseOnReturn(source, v, ret) and
  result =
    "Sensitive stack variable '" + v.getName() +
    "' is written or copied here and can reach $@ without OPENSSL_cleanse."
}

from ControlFlowNode source, StackVariable v, ReturnStmt ret, string message
where
  message = reportMessage(source, v, ret)
select source, message, ret, "this return"
