// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "crypto/scrypt.h"
#include "streams.h"

uint256 CBlockHeader::GetHash(const Consensus::Params& params) const
{
    int version;
    if (nHeight >= (uint32_t)params.XLCHeight) {
        version = PROTOCOL_VERSION;
    } else {
        version = PROTOCOL_VERSION | SERIALIZE_BLOCK_LEGACY;
    }
    CHashWriter writer(SER_GETHASH, version);
    ::Serialize(writer, *this);
    return writer.GetHash();
}

uint256 CBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}

uint256 CBlockHeader::GetPoWHash() const
{
    int version;
    const Consensus::Params& params = Params().GetConsensus();
    if (nHeight >= (uint32_t)params.XLCHeight) {
        version = PROTOCOL_VERSION;
        return GetHash();//hard fork;
    } else {
        version = PROTOCOL_VERSION | SERIALIZE_BLOCK_LEGACY;
        return GetHash();//hard fork;
    }
    CDataStream ss(SER_NETWORK,version);
    ss << *this;
    assert(ss.size()==80);
    uint256 thash;
    scrypt_1024_1_1_256(BEGIN(ss[0]), BEGIN(thash));
    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce.GetHex(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
