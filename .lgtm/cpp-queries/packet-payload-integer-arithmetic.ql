/** 
* @name Suspicious packet->payload based integer arithmetic
* @description An arithmetic operation influenced array access is suspicious 
* if it uses an integer value that is likely to be network-controlled, and
* may require a closer manual audit.
* @kind problem
* @problem.severity warning
* @id cpp/packet-payload-integer-arithmetic
* @tags audit security
*/

import cpp

import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis

/** A source of an integer value that is likely to come from the network.
 * This is produced by an invocation of a macro of the form `ntoh*` or `get_u_int*_t`,
 * called with `packet->payload` as an argument.
 */

class NetworkMacro extends Macro {
  NetworkMacro() { this.getName().regexpMatch("^ntoh(ll|l|s)") }
}

class NetworkIntegerSource extends Expr {
  NetworkIntegerSource() {
    exists(MacroInvocation mi |
      this = mi.getExpr() and
      mi.getUnexpandedArgument(0).regexpMatch(".*packet->payload.*") |
      // catch all get_u_int*_t(x)
      mi.getMacroName().regexpMatch("^get_u_int(64|32|16|8)_t") and
      // dedup ntoh*(get_u_int*_t(x)) since we'll catch those in the next case
      not mi.getOutermostMacroAccess().getMacro() instanceof NetworkMacro
      or
      // catch all ntoh*(x) ... this will also catch the nested cases
      mi.getMacro() instanceof NetworkMacro
    )
  }
}

class ArithmeticOperation extends Operation {
  ArithmeticOperation() {
    this instanceof UnaryArithmeticOperation or this instanceof BinaryArithmeticOperation
  }
}

class NetworkToArrayAccess extends TaintTracking::Configuration {
  NetworkToArrayAccess() { this = "NetworkToArrayAccess" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkIntegerSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ArrayExpr ae | sink.asExpr() = ae.getArrayOffset())
  }
}

class NetworkToArithmetic extends TaintTracking::Configuration {
  NetworkToArithmetic() { this = "NetworkToArithmetic" }

  override predicate isSource(DataFlow::Node source) {
       source.asExpr() instanceof NetworkIntegerSource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    exists (Assignment assign |
        sink.asExpr() = assign.getRValue().(ArithmeticOperation) or
        sink.asExpr() = assign.(AssignArithmeticOperation) 
    ) or
    exists(LocalVariable var | 
      sink.asExpr() = var.getInitializer().getExpr().(ArithmeticOperation)
    )
  }  
}

// find audit candidates based on suspicious network integer use
from NetworkIntegerSource source, Expr sink1, Expr sink2, NetworkToArithmetic config1, NetworkToArrayAccess config2
where config1.hasFlow(DataFlow::exprNode(source), DataFlow::exprNode(sink1))
      // or this if you want integer arithmeric _OR_ array accesses
      and config2.hasFlow(DataFlow::exprNode(source), DataFlow::exprNode(sink2))
select source, "Suspicious use of network integer arithmetic."
