/** @kind path-problem */
import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/** Macro come ntohl, ntohs, etc. */
class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mac |
      mac.getMacro().getName().matches("ntoh%") and
      this = mac.getExpr()
    )
  }
}

/** Configurazione per taint tracking con validazione */
module NetworkMemcpyConfig implements DataFlow::ConfigSig {
  
  /** Sorgente: espressione derivata da ntoh* */
  predicate isSource(DataFlow::Node n) {
    n.asExpr() instanceof NetworkByteSwap
  }

  /** Sink: terzo argomento di memcpy (length) */
  predicate isSink(DataFlow::Node n) {
    exists(FunctionCall memcpy |
      memcpy.getTarget().getName() = "memcpy" and
      n.asExpr() = memcpy.getArgument(2)
    )
  }

  predicate isBarrier(DataFlow::Node n) {
    exists(BinaryOperation op, IfStmt ifs |
      n.asExpr() = op and
      ifs.getCondition() = op and
      op.getOperator() in ["<", "<=", ">", ">="]
    )
  }
}


/** Tracciamento del flusso */
module Flow = DataFlow::Global<NetworkMemcpyConfig>;
import Flow::PathGraph


from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink, src, sink, "Unvalidated network data reaches memcpy length parameter."