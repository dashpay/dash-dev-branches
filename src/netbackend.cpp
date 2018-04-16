// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "netbackend.h"

namespace {
    class CRegistry {
        CNetBackend::all_t elems_;
        CRegistry() {}
        static CRegistry& instance() {
            static CRegistry inst;
            return inst;
        }
    public:
        static const CNetBackend::all_t& elems() {
            return instance().elems_;
        }
        static void add(const CNetBackend& elem) {
            instance().elems_.emplace_back(elem);
        }
    };
}

CNetBackend::CNetBackend()
{
    CRegistry::add(*this);
}

const CNetBackend::all_t& CNetBackend::all()
{
    return CRegistry::elems();
}
