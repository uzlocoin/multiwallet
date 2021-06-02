package util

import "github.com/OpenBazaar/wallet-interface"

type ExtCoinType wallet.CoinType

func ExtendCoinType(coinType wallet.CoinType) ExtCoinType {
	return ExtCoinType(uint32(coinType))
}

const (
	CoinTypeUzlocoin     ExtCoinType = 444
	CoinTypeUzlocoinTest             = 1000444
)

func (c *ExtCoinType) String() string {
	ct := wallet.CoinType(uint32(*c))
	str := ct.String()
	if str != "" {
		return str
	}

	switch *c {
	case CoinTypeUzlocoin:
		return "Uzlocoin"
	case CoinTypeUzlocoinTest:
		return "Testnet Uzlocoin"
	default:
		return ""
	}
}

func (c *ExtCoinType) CurrencyCode() string {
	ct := wallet.CoinType(uint32(*c))
	str := ct.CurrencyCode()
	if str != "" {
		return str
	}

	switch *c {
	case CoinTypeUzlocoin:
		return "PHR"
	case CoinTypeUzlocoinTest:
		return "TPHR"
	default:
		return ""
	}
}

func (c ExtCoinType) ToCoinType() wallet.CoinType {
	return wallet.CoinType(uint32(c))
}
