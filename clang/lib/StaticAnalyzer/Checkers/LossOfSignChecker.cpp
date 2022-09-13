//== LossOfSignChecker.cpp - Loss of sign checker -----*- C/C++ -*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This defines LossOfSignChecker, which performs checks for assignment of
// signed negative values to unsigned variables.
//
//===----------------------------------------------------------------------===//
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class LossOfSignChecker
    : public Checker<check::Bind /*, check::ASTDecl<VarDecl> */> {
  mutable std::unique_ptr<BuiltinBug> BT;
  void emitReport(ProgramStateRef state, CheckerContext &C,
                  bool IsTainted = false) const;

public:
  void checkBind(SVal loc, SVal val, const Stmt *S, CheckerContext &C) const;
};
} // end anonymous namespace

void LossOfSignChecker::emitReport(ProgramStateRef St, CheckerContext &C,
                                   bool IsTainted) const {
  if (ExplodedNode *N = C.generateNonFatalErrorNode(St)) {
    if (!BT) {
      BT.reset(new BuiltinBug(this, "assigning negative value to "
                                    "a plain char variable loses sign "
                                    "and may cause undesired runtime "
                                    "behavior"));
    }
    StringRef Msg = IsTainted ? "Might assign negative value to "
                                "plain char "
                              : BT->getDescription();
    C.emitReport(std::make_unique<PathSensitiveBugReport>(*BT, Msg, N));
  }
}

bool isPlainCharType(QualType Ty) {
  if (const auto *BT = dyn_cast<BuiltinType>(Ty)) {
    return BT->getKind() == BuiltinType::Char_U ||
           BT->getKind() == BuiltinType::Char_S;
  }
  return false;
}
void LossOfSignChecker::checkBind(SVal loc, SVal val, const Stmt *S,
                                  CheckerContext &C) const {

  const TypedValueRegion *TR =
      dyn_cast_or_null<TypedValueRegion>(loc.getAsRegion());

  if (!TR)
    return;

  QualType valTy = TR->getValueType();
  if (!isPlainCharType(valTy))
    return;

  // Get the value of the right-hand side.  We only care about values
  // that are defined (UnknownVals and UndefinedVals are handled by other
  // checkers).
  Optional<NonLoc> NV = val.getAs<NonLoc>();
  if (!NV)
    return;

  ProgramStateRef state = C.getState();
  SValBuilder &svalBuilder = C.getSValBuilder();
  DefinedOrUnknownSVal Zero = svalBuilder.makeZeroVal(valTy);
  ConstraintManager &CM = C.getConstraintManager();
  SVal Eval = svalBuilder.evalBinOp(state, BO_LT, *NV, Zero,
                                    svalBuilder.getConditionType());
  if (Eval.isUnknownOrUndef())
    return;

  if (Optional<DefinedSVal> LessThanZeroDVal = Eval.getAs<DefinedSVal>()) {
    ProgramStateRef StatePos, StateNeg;

    std::tie(StateNeg, StatePos) =
        CM.assumeDual(C.getState(), *LessThanZeroDVal);

    if (!StatePos)
      emitReport(StateNeg, C);
    if (StateNeg && StatePos && taint::isTainted(state, *NV)) {
      // Binding of a negative value to a unsigned location.
      emitReport(StateNeg, C, true);
    }
  }
}

void ento::registerLossOfSignChecker(CheckerManager &mgr) {
  mgr.registerChecker<LossOfSignChecker>();
}
bool ento::shouldRegisterLossOfSignChecker(const CheckerManager &mgr) {
  return true;
}
