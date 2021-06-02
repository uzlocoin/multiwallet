package uzlocoin

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"math/big"
	"time"
)

// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// mainPowLimit is the highest proof of work value a Bitcoin block can
	// have for the main network.  It is the value 2^224 - 1.
	mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)
)

const (
	// MainNet represents the main bitcoin network.
	MainUzlocoinNet wire.BitcoinNet = 0x504852   // PHR
	TestUzlocoinNet wire.BitcoinNet = 0x545048   // TP
)

var UzlocoinMainNetParams = chaincfg.Params{
	Name:        "mainUzlocoin",
	Net:         MainUzlocoinNet,
	DefaultPort: "6331",
	DNSSeeds: []chaincfg.DNSSeed{
		{"45.93.100.49", true},
		{"seeder.unibankwallet.com", true},
	},

	// Chain parameters
	GenesisBlock:     nil, // unused
	GenesisHash:      nil, // unused
	PowLimit:         mainPowLimit,
	PowLimitBits:     0x207fffff,
	BIP0034Height:    0, // unused
	BIP0065Height:    0, // unused
	BIP0066Height:    0, // unused
	CoinbaseMaturity: 50,
	TargetTimespan:   time.Minute, // 1 minute
	//PoSTargetTimespan:        time.Minute * 40,
	TargetTimePerBlock:       time.Minute, // 1 minutes
	RetargetAdjustmentFactor: 4,           // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        true,
	//MasternodeDriftCount:     20,
	//LastPoWBlock:             999999999,
	//ZerocoinStartHeight:      89993,
	//ZerocoinLastOldParams:    99999999,
	//StakeMinimumAge:          time.Hour * 3,
	//ModifierV2StartBlock:     433160,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []chaincfg.Checkpoint{},

	// Mempool parameters
	RelayNonStdTxs: false,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "uz", // always bc for main net

	// Address encoding magics
	PubKeyHashAddrID: 0x37, // starts with 1
	ScriptHashAddrID: 0x0d, // starts with 3
	PrivateKeyID:     0xd4, // starts with 5 (uncompressed) or K (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x02, 0x2d, 0x25, 0x33}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x02, 0x21, 0x31, 0x2b}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0x800001bc,
}

var UzlocoinTestNetParams = chaincfg.Params{
	Name:        "testnetUzlocoin",
	Net:         TestUzlocoinNet,
	DefaultPort: "11773",
	DNSSeeds: []chaincfg.DNSSeed{
	},

	// Chain parameters
	GenesisBlock:     nil, // unused
	GenesisHash:      nil, // unused
	PowLimit:         mainPowLimit,
	PowLimitBits:     0x207fffff,
	BIP0034Height:    0, // unused
	BIP0065Height:    0, // unused
	BIP0066Height:    0, // unused
	CoinbaseMaturity: 50,
	TargetTimespan:   time.Minute, // 1 minute
	TargetTimePerBlock:       time.Minute, // 1 minutes
	RetargetAdjustmentFactor: 4,           // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        true,
	Checkpoints: []chaincfg.Checkpoint{},
	RelayNonStdTxs: false,
	Bech32HRPSegwit: "tp",

	PubKeyHashAddrID: 0x8B, // starts with x or y
	ScriptHashAddrID: 0x13, // starts with 8 or 9
	PrivateKeyID:     0xEF, // starts with '9' or 'c' (Bitcoin defaults)

	HDPrivateKeyID: [4]byte{0x3a, 0x80, 0x61, 0xa0},
	HDPublicKeyID:  [4]byte{0x3a, 0x80, 0x58, 0x37},

	HDCoinType: 0x80000001,
}
