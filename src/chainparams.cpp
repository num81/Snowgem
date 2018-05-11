// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "base58.h"

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Snowgem' + blake2s(b'2018-01-01 Snowgem is born.').hexdigest()
 */

static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Snowgema9f525a520bea48ab5628cec79ee0af33cf234bea3ee106db4a76233243896e0";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "XSG";
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 8000;
        consensus.nSubsidyHalvingInterval = 60 * 24 * 365 * 4;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        consensus.nMasternodePaymentsStartBlock = 193200;
        consensus.nMasternodePaymentsIncreasePeriod = 43200; // 1 month

        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 1 * 60; // 1 min
        /**
         * The message start string should be awesome! Ⓢ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xc8;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("04b7ecf0baa90495ceb4e4090f6b2fd37eec1e9c85fac68a487f3ce11589692e4a317479316ee814e066638e1db54e37a10689b70286e6315b1087b6615d179264");
        nDefaultPort = 16113;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        nMasternodeCountDrift = 0;

        genesis = CreateGenesisBlock(
            1511112234,
            uint256S("0x00000000000000000000000000000000000000000000000000000000000002f2"),
            ParseHex("0080175e5d83d4e89e4c536eb9e7e2ceef26594e8a015ed964fdc851c77a99b0c286d2aeed062babf5d8150fe4decef5a0cbe1e601b43b30fbe149e4521c9926bbfd004c8ae9233914475c3ddffc936dc01f0f01013d92ab9c92af1d5a16a4723f6cabc2e42e7f293f26f29db1c650e64b720e83b53b5c81a9727851bd475abee6428ae3eddbdb091682bcd597268e821736067089afe84d5cc4a723f7b70ed7ef15eb23b35b45cb01c5f595b31a2f97ed005525aae3c47deb4395127a11d23158ea8556215e4af536c8774dae96023d676d12d23d4a99ee86218544c91a65d0e4235a1bdea78a2818e20b9e16b5354520447866bbb9fa6ec77602f807faf2a664ce4a3bfe4611c46cfd1a888ecee96a6825064a28a1da8fa92073c4d2067842a540cedbbf590dba21338a976b9ee1532110dc9bcf208886934c091dce2603dad694f54bac04401b71a7d9c6d0911f030177d23254cecadc9cdf31647e319873977a7fe0600ada5d71e3f887f3d04a243727c8645f1887dbcd7c137c41a0895a2df9dbd2d3d5a778937610ab95442723706d6fbbdfcc11b85be2ccfddb8008c69df84ba1078752ba6227a16ff545f5995cd88df5bdf13fd341222989ebe6179d95db496275ef6e94e4a48998fc9d0fa4f6729b54ee733f8c82f882aab36dfe7adc45ee3bd7bd984e5e16e1639f76ea41edb957859bfc8c90082abf4c17df39d1680691a0599a5912beca3db56c1c0db0f18550b221e0653343bcbc4f42badf1bb8c70d49a411d9e266215ec0a1a8bc999015450c8e35691801051b1364d0ebc5cae37361a754d67fb37d60d309fa5edebeaaedd7ad4c248768c7220b1da23bafdb0f325acdf656d60750da2424feef0da965975bb1ca14ea142ccc96431be3a96729e26bbc9684f096aa2015ece7f8324a0103fba4a32bc2b19f64de8312866400ddbe1bef67e7b5586d40c8da1eeba0c6f3877a022a76b1c46454a1c30100448c4f6a6eaa5e44962c980225635c9fe039cb6173311270c5109597d5bcd7be157d48eaa76b2f9badb6a743a75ba19ae409bcf60b0d0f9d71eef3643dd61d8697483f31ab24685d7e8b59016b3ea96d80cdad01273b38c15cee7996bb438b2465421de8e6a129d029c58958d6605612975fc97844a55d477293d8b6c105f789226ae77216915bda47061cd2019e9d2f1bd1c301bda34d070e4e32d8c64e062914953a83832b6a636097b4429b11b1bb91e92e1503f0d45c620a4dfaf4820e76e6f108e9da9dc30919eb843cbada3306f266734e72a21695ce69503795110a9649740aa6e5151673ae34f66b866903d7f21820f7227be019906d86dbd412f92ad6e54321ce104813ebb362f4a5faa593819162874a2f0a4ef8d827cf1ab06d5410157a37370632da9e4dead1a2232fb4000711fcaa4683529a5638d775d5f4dc52515f7be7241a3df4b29d8f6a578f72a4da3de1cb49aeda1988620ef2149b05f1ebd9bd94f586b8cabefe263bbeb39a23ac652b5c0be4931598f968f7d5bcdb46329d52810a87a0b132c423f51a4cc2e071b15042f70d3d724e2ab7d7f12aee3d9bc3c7389f197dd73a49d5f5a5e70d0bbd8ef41c17854db3212d478b18e8b5e237667435e086733a5e88b97fe6a4b9772ac3638e019e199d08400db3405be1c1c9a8a205a1191308cfa7f3e1e223a6c982ac537603a13c042f687cb98e0e91f31ec82a3fce1350a60dad685d8456e6276791633ab98f0268de2ba91aaddf1572fe46bfede47e123519f2bd120e2e190ee54cdd90865b766299c5ba6ac209bca8801a6f4e1f13175712ddd8e22ddcc8d104c2415225e017b73fbcda6fb3b7c318d783fd518346da467fa3ea475c3506c0996ec1daa63c0a037f88531f151e428f"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0002aa5b2375507215e020d53aea7687e34db9818b468948c5128951b8908dc2"));
        assert(genesis.hashMerkleRoot == uint256S("1be7bd8f6e87013f33c4148f3027aa32285d9cff70f5c52af83fca43e5f113da"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.push_back(CDNSSeedData("dnsseed1.snowgem.org", "dnsseed1.snowgem.org")); //Snowgem seed node
        vSeeds.push_back(CDNSSeedData("dnsseed2.snowgem.org", "dnsseed2.snowgem.org")); //Snowgem seed node
        vSeeds.push_back(CDNSSeedData("dnsseed3.snowgem.org", "dnsseed3.snowgem.org")); //Snowgem seed node
        vSeeds.push_back(CDNSSeedData("abctoxyz.site", "dnsseed.abctoxyz.site")); //Snowgem seed node

        // guarantees the first 2 characters, when base58 encoded, are "s1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0x28};
        // guarantees the first 2 characters, when base58 encoded, are "s3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0x2D};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
		fHeadersFirstSyncingActive = false;
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock)
            (23000, uint256S("0x000000006b366d2c1649a6ebb4787ac2b39c422f451880bc922e3a6fbd723616"))
            (88000, uint256S("0x0000003ef01c0d1f954fdd738dac1b4f7191e6bee66ed8cb882d00d65fccd89b")),
            1519442392,     // * UNIX timestamp of last checkpoint block
            194812,         // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1275            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "s3d27MhkBRt3ha2UuxhjXaYF4DCnttTMnL1", /* main-index: 0*/
            "s3Wws6Mx3GHJkAe8QkNr4jhW28WU21Fp9gL", /* main-index: 1*/
            "s3QD18CKEA9Cw4kgnssnmk4rbf9Y3rU1uWG", /* main-index: 2*/
            "s3esoTmHdcXdDwCkoGSxC4YkfzBo1ySuher", /* main-index: 3*/
            "s3Q8NwoBv4aq9RRvqjT3LqN9TQnZrS2RdcV", /* main-index: 4*/
            "s3ix12RLstrzFEJKVsbLxCsPuUSjAqs3Bqp", /* main-index: 5*/
            "s3bCvm5zDv9KYFwHxaZjz2eKecEnbdFz98f", /* main-index: 6*/
            "s3UfvUuHahzTmYViL3KrGZeUPug69denBm3", /* main-index: 7*/
            "s3gmzNUmttwDJbUcpmW4gxVqHf3J58fDKpp", /* main-index: 8*/
            "s3YuWMW4Kpij7gW91WHLhjfi5Dwc7dKyPNn", /* main-index: 9*/
            "s3k2MaTdZyFBqyndrHdCDFnET5atCdC4iod", /* main-index: 10*/
            "s3YFHxL9euG89LMgPT5wGka4Ek8XVyw4FWG", /* main-index: 11*/
            "s3TKKkNnvBXphdv4ce84UKePdssWLHGBe1A", /* main-index: 12*/
            "s3PLrY7e7jzzAxnMY7A6GkjhkGc1CVkuEoi", /* main-index: 13*/
            "s3Ug8VAGcUijwD6QMhyFcCYXQEFABaA9VFy", /* main-index: 14*/
            "s3b4DAbbrTb4FPz3mHeyE89fUq6Liqg5vxX", /* main-index: 15*/
            "s3cM379BTJyCe5yJC4jkPn6qJwpZaHK2kXb", /* main-index: 16*/
            "s3TKWLar6bZEHppF4ZR1MbPuBfe33a1bHX9", /* main-index: 17*/
            "s3UpY6Q3T3v3F7MEpNDnV3rTucLEJkkHR4q", /* main-index: 18*/
            "s3eWx3DcwLiusTBfhWu6z7zM4TffaV1Ng9r", /* main-index: 19*/
        };
        nPoolMaxTransactions = 3;
        strSporkKey = "045da9271f5d9df405d9e83c7c7e62e9c831cc85c51ffaa6b515c4f9c845dec4bf256460003f26ba9d394a17cb57e6759fe231eca75b801c20bccd19cbe4b7942d";

        strObfuscationPoolDummyAddress = "s1eQnJdoWDhKhxDrX8ev3aFjb1J6ZwXCxUT";
        nStartMasternodePayments = 1523750400; //2018-04-15
        nBudget_Fee_Confirmations = 6; // Number of confirmations for the finalization fee
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "SNGT";
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 8000;
        consensus.nSubsidyHalvingInterval = 60 * 24 * 365 * 4;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.nMasternodePaymentsStartBlock = 1500;
        consensus.nMasternodePaymentsIncreasePeriod = 200;
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("044e7a1553392325c871c5ace5d6ad73501c66f4c185d6b0453cf45dec5a1322e705c672ac1a27ef7cdaf588c10effdf50ed5f95f85f2f54a5f6159fca394ed0c6");
        nDefaultPort = 26113;
		nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
		nEquihashK = K;
		
    	genesis = CreateGenesisBlock(
            1511112234,
            uint256S("0x00000000000000000000000000000000000000000000000000000000000002f2"),
            ParseHex("0080175e5d83d4e89e4c536eb9e7e2ceef26594e8a015ed964fdc851c77a99b0c286d2aeed062babf5d8150fe4decef5a0cbe1e601b43b30fbe149e4521c9926bbfd004c8ae9233914475c3ddffc936dc01f0f01013d92ab9c92af1d5a16a4723f6cabc2e42e7f293f26f29db1c650e64b720e83b53b5c81a9727851bd475abee6428ae3eddbdb091682bcd597268e821736067089afe84d5cc4a723f7b70ed7ef15eb23b35b45cb01c5f595b31a2f97ed005525aae3c47deb4395127a11d23158ea8556215e4af536c8774dae96023d676d12d23d4a99ee86218544c91a65d0e4235a1bdea78a2818e20b9e16b5354520447866bbb9fa6ec77602f807faf2a664ce4a3bfe4611c46cfd1a888ecee96a6825064a28a1da8fa92073c4d2067842a540cedbbf590dba21338a976b9ee1532110dc9bcf208886934c091dce2603dad694f54bac04401b71a7d9c6d0911f030177d23254cecadc9cdf31647e319873977a7fe0600ada5d71e3f887f3d04a243727c8645f1887dbcd7c137c41a0895a2df9dbd2d3d5a778937610ab95442723706d6fbbdfcc11b85be2ccfddb8008c69df84ba1078752ba6227a16ff545f5995cd88df5bdf13fd341222989ebe6179d95db496275ef6e94e4a48998fc9d0fa4f6729b54ee733f8c82f882aab36dfe7adc45ee3bd7bd984e5e16e1639f76ea41edb957859bfc8c90082abf4c17df39d1680691a0599a5912beca3db56c1c0db0f18550b221e0653343bcbc4f42badf1bb8c70d49a411d9e266215ec0a1a8bc999015450c8e35691801051b1364d0ebc5cae37361a754d67fb37d60d309fa5edebeaaedd7ad4c248768c7220b1da23bafdb0f325acdf656d60750da2424feef0da965975bb1ca14ea142ccc96431be3a96729e26bbc9684f096aa2015ece7f8324a0103fba4a32bc2b19f64de8312866400ddbe1bef67e7b5586d40c8da1eeba0c6f3877a022a76b1c46454a1c30100448c4f6a6eaa5e44962c980225635c9fe039cb6173311270c5109597d5bcd7be157d48eaa76b2f9badb6a743a75ba19ae409bcf60b0d0f9d71eef3643dd61d8697483f31ab24685d7e8b59016b3ea96d80cdad01273b38c15cee7996bb438b2465421de8e6a129d029c58958d6605612975fc97844a55d477293d8b6c105f789226ae77216915bda47061cd2019e9d2f1bd1c301bda34d070e4e32d8c64e062914953a83832b6a636097b4429b11b1bb91e92e1503f0d45c620a4dfaf4820e76e6f108e9da9dc30919eb843cbada3306f266734e72a21695ce69503795110a9649740aa6e5151673ae34f66b866903d7f21820f7227be019906d86dbd412f92ad6e54321ce104813ebb362f4a5faa593819162874a2f0a4ef8d827cf1ab06d5410157a37370632da9e4dead1a2232fb4000711fcaa4683529a5638d775d5f4dc52515f7be7241a3df4b29d8f6a578f72a4da3de1cb49aeda1988620ef2149b05f1ebd9bd94f586b8cabefe263bbeb39a23ac652b5c0be4931598f968f7d5bcdb46329d52810a87a0b132c423f51a4cc2e071b15042f70d3d724e2ab7d7f12aee3d9bc3c7389f197dd73a49d5f5a5e70d0bbd8ef41c17854db3212d478b18e8b5e237667435e086733a5e88b97fe6a4b9772ac3638e019e199d08400db3405be1c1c9a8a205a1191308cfa7f3e1e223a6c982ac537603a13c042f687cb98e0e91f31ec82a3fce1350a60dad685d8456e6276791633ab98f0268de2ba91aaddf1572fe46bfede47e123519f2bd120e2e190ee54cdd90865b766299c5ba6ac209bca8801a6f4e1f13175712ddd8e22ddcc8d104c2415225e017b73fbcda6fb3b7c318d783fd518346da467fa3ea475c3506c0996ec1daa63c0a037f88531f151e428f"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0002aa5b2375507215e020d53aea7687e34db9818b468948c5128951b8908dc2"));
        assert(genesis.hashMerkleRoot == uint256S("1be7bd8f6e87013f33c4148f3027aa32285d9cff70f5c52af83fca43e5f113da"));


        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("abctoxyz.site", "dnsseed.testnet.abctoxyz.site")); // Snowgem
        vSeeds.push_back(CDNSSeedData("snowgem.org", "dnsseed.testnet.snowgem.org")); // Snowgem

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

		checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1477774444,  // * UNIX timestamp of last checkpoint block
            0,       // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            715          //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi"
            };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
		
		nStartMasternodePayments = 1520121600; //2018-03-04
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 1 * 60;

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 26114;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
    	genesis = CreateGenesisBlock(
            1296688602,
            uint256S("000000000000000000000000000000000000000000000000000000000000000c"),
            ParseHex("0a8ede36c2a99253574258d60b5607d65d6f10bb9b8df93e5e51802620a2b1f503e22195"),
            0x200f0f0f, 4, 0);
			
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x047c30b7734dbad47335383f9997a5d5d8d5e4b46fd0f02f23ec4fca27651b41"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            0,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { "t2f9nkUG1Xe2TrQ4StHKcxUgLGuYszo8iS4" };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CBitcoinAddress address(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(address.IsValid());
    assert(address.IsScript());
    CScriptID scriptID = boost::get<CScriptID>(address.Get()); // Get() returns a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}
