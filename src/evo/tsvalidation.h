// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_TSVALIDATION_H
#define DASH_TSVALIDATION_H

#include "transition.h"
#include "validation.h"

class CEvoUser;

// TODO define good min/max fees
static const CAmount EVO_TS_MIN_FEE = (CAmount)(0.01 * COIN);
static const CAmount EVO_TS_MAX_FEE = (CAmount)(0.10 * COIN);
static const size_t EVO_TS_MAX_SIZE = 1500; // TODO find correct max size

bool CheckTransitionForUser(const CTransition &ts, const CEvoUser &user, bool checkSigs, CValidationState &state);
bool ProcessTransitionForUser(const CTransition &ts, CEvoUser &user, CValidationState &state);
bool ProcessTransitionsInBlock(const CBlock &block, bool onlyCheck, CValidationState &state);
bool UndoTransitionsInBlock(const CBlock &block, CValidationState &state);

#endif //DASH_TSVALIDATION_H
