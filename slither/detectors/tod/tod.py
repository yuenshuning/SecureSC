from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.analyses.data_dependency.data_dependency import (
    is_dependent,
    is_dependent_ssa,
    get_dependencies,
    get_dependencies_ssa
)
from slither.core.cfg.node import NodeType
from slither.core.declarations import Function
from slither.core.declarations.function_top_level import FunctionTopLevel
from slither.core.solidity_types import MappingType, ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations.solidity_variables import (
    SolidityVariable,
    SolidityVariableComposed,
    SolidityFunction,
)
from slither.slithir.operations import (
    Assignment,
    Binary,
    BinaryType,
    HighLevelCall,
    SolidityCall,
)
from slither.slithir.variables import (
    TemporaryVariable,
    ReferenceVariable
)

class TOD(AbstractDetector):
    """
    Detect function named TOD
    """

    ARGUMENT = "TOD"  # slither will launch the detector with slither.py --mydetector
    HELP = "Transaction Ordering Dependency"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = ".."
    WIKI_TITLE = ".."
    WIKI_DESCRIPTION = ".."
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."

    sources_taint = [
        SolidityVariable("now"),
        SolidityVariableComposed("block.number"),
        SolidityVariableComposed("block.timestamp"),
    ]

    @staticmethod
    def is_direct_comparison(ir):
        return isinstance(ir, Binary) and ir.type == BinaryType.EQUAL

    @staticmethod
    def is_any_tainted(variables, taints, function) -> bool:
        return any(
            (
                is_dependent(var, taint, function.contract)
                for var in variables
                for taint in taints
            )
        )

    @staticmethod
    def is_any_tainted_ssa(variables, taints, function) -> bool:
        return any(
            (
                is_dependent_ssa(var, taint, function.contract)
                for var in variables
                for taint in taints
            )
        )

    def taint_source(self, func):
        taints = []
        return taints

    # Retrieve all tainted (node, function) pairs
    def tainted_nodes(self, func, taints):
        results = []
        taints += self.sources_taint

        # Disable the detector on top level function until we have good taint on those
        if isinstance(func, FunctionTopLevel):
            return results
        for node in func.nodes:
            # case Init Node:

            # case Assignment Node: Explicit-taint-analysis (Data Dependency)
            if node.type in [NodeType.EXPRESSION, NodeType.VARIABLE]: # msg.sender.transfer(REWARD) is also EXPRESSION
                for ir in node.irs:             # node.irs_ssa
                    # Filter to only tainted
                    for var in ir.used:
                        if self.is_any_tainted([var], taints, func):
                            if not any([
                                var.name == v.name
                                for v in taints
                            ]):
                                taints.append(var)
            # case IF / IF_LOOP / BEGIN_LOOP: Implicit-taint-analysis (Control Dependency)
            elif node.type in [NodeType.IF]:
                for ir in node.irs:             # node.irs_ssa
                    for var in ir.used:
                        if self.is_any_tainted([var], taints, func):
                            if node not in results:
                                results.append(node)
            
            # case require / assert, like require(a > b OR c is in d): Decontamination

            # case Transfer / Selfdestruct / transferFrom(address,address,uint256): sink

                
        return results

    def detect_tod(self, func, tainted_state):
        
        # Taint Source
        # parameter
        tainted_param = func.parameters_ssa         # func.parameters or func.parameters_ssa
        tainted_param = func.parameters
        taints = tainted_state + tainted_param
        
        # Accumulate tainted (node,function) pairs involved in strict equality (==) comparisons
        results = self.tainted_nodes(func, taints)
        return results

    # TODO: state dependency taint analysis
    def get_tainted_state(self, contract):
        """
        Tainted state variables
        """
        res = []
        if contract.is_top_level:
            return res
        for v in contract.state_variables:
            dep = {
                    d.name
                    for d in get_dependencies(v, contract)
                    if not isinstance(d, (TemporaryVariable, ReferenceVariable)) and d.name != v.name
                }
            if len(dep) > 0:
                res.append(v) 
        return res

    # TODO: state dependency taint analysis
    def get_tainted_state_ssa(self, contract):
        """
        Tainted state variables
        """
        res = []
        if contract.is_top_level:
            return res
        for v in contract._initial_state_variables:
            # GUESS_0, get_dependencies_ssa - GUESS_1
            dep = {
                    d.name
                    for d in get_dependencies_ssa(v, contract)
                    if not isinstance(d, (TemporaryVariable, ReferenceVariable)) and d.name != v.name
                }
            if len(dep) > 0:
                res.append(v.name) 
        return res

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts_derived:
            # funcs = contract.all_functions_called + contract.modifiers
            # non ssa
            tainted_state = self.get_tainted_state(contract)
            # for key in contract.context["DATA_DEPENDENCY_SSA"].keys():
            #     print(key, '====')
            #     for i in contract.context["DATA_DEPENDENCY_SSA"][key]:
            #         print(i)

            for func in contract.functions:
                if (
                    func.visibility in ["private"]
                    or func.is_constructor
                    or func.is_fallback
                    or func.is_constructor_variables
                    or not func.is_implemented
                ):
                    continue
                
                info = [func, "transaction ordering dependency\n"]
                info += ["\tTransaction Ordering Dependency:\n"]
                
                taint_nodes = self.detect_tod(func, tainted_state)
                
                # sort the nodes to get deterministic results
                taint_nodes.sort(key=lambda x: x.node_id)

                for node in taint_nodes:
                    info += ["\t- ", node, "\n"]

                res = self.generate_result(info)

                results.append(res)

        return results