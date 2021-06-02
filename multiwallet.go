package multiwallet

import (
	"errors"
	"github.com/uzlocoin/multiwallet/uzlocoin"
	"strings"
	"time"

	"github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/op/go-logging"
	eth "github.com/uzlocoin/go-ethwallet/wallet"
	"github.com/uzlocoin/multiwallet/bitcoin"
	"github.com/uzlocoin/multiwallet/bitcoincash"
	"github.com/uzlocoin/multiwallet/client/blockbook"
	"github.com/uzlocoin/multiwallet/config"
	"github.com/uzlocoin/multiwallet/litecoin"
	"github.com/uzlocoin/multiwallet/service"
	"github.com/uzlocoin/multiwallet/util"
	"github.com/uzlocoin/multiwallet/zcash"
	"github.com/tyler-smith/go-bip39"
)

var log = logging.MustGetLogger("multiwallet")

var UnsuppertedCoinError = errors.New("multiwallet does not contain an implementation for the given coin")

type MultiWallet map[util.ExtCoinType]wallet.Wallet

func NewMultiWallet(cfg *config.Config) (MultiWallet, error) {
	log.SetBackend(logging.AddModuleLevel(cfg.Logger))
	service.Log = log
	blockbook.Log = log

	if cfg.Mnemonic == "" {
		ent, err := bip39.NewEntropy(256)
		if err != nil {
			return nil, err
		}
		mnemonic, err := bip39.NewMnemonic(ent)
		if err != nil {
			return nil, err
		}
		cfg.Mnemonic = mnemonic
		cfg.CreationDate = time.Now()
	}

	multiwallet := make(MultiWallet)
	var err error
	for _, coin := range cfg.Coins {
		var w wallet.Wallet
		switch coin.CoinType {
		case util.CoinTypeUzlocoin:
			var params chaincfg.Params
			if cfg.Params.Name == uzlocoin.UzlocoinMainNetParams.Name {
				params = uzlocoin.UzlocoinMainNetParams
			} else {
				params = uzlocoin.UzlocoinTestNetParams
			}
			w, err = uzlocoin.NewUzlocoinWallet(coin, cfg.Mnemonic, &params, cfg.Proxy, cfg.Cache, cfg.DisableExchangeRates)
			if err != nil {
				return nil, err
			}
			if cfg.Params.Name == uzlocoin.UzlocoinMainNetParams.Name {
				multiwallet[util.CoinTypeUzlocoin] = w
			} else {
				multiwallet[util.CoinTypeUzlocoinTest] = w
			}
		case util.ExtendCoinType(wallet.Bitcoin):
			w, err = bitcoin.NewBitcoinWallet(coin, cfg.Mnemonic, cfg.Params, cfg.Proxy, cfg.Cache, cfg.DisableExchangeRates)
			if err != nil {
				return nil, err
			}
			if cfg.Params.Name == chaincfg.MainNetParams.Name {
				multiwallet[util.ExtendCoinType(wallet.Bitcoin)] = w
			} else {
				multiwallet[util.ExtendCoinType(wallet.TestnetBitcoin)] = w
			}
		case util.ExtendCoinType(wallet.BitcoinCash):
			w, err = bitcoincash.NewBitcoinCashWallet(coin, cfg.Mnemonic, cfg.Params, cfg.Proxy, cfg.Cache, cfg.DisableExchangeRates)
			if err != nil {
				return nil, err
			}
			if cfg.Params.Name == chaincfg.MainNetParams.Name {
				multiwallet[util.ExtendCoinType(wallet.BitcoinCash)] = w
			} else {
				multiwallet[util.ExtendCoinType(wallet.TestnetBitcoinCash)] = w
			}
		case util.ExtendCoinType(wallet.Zcash):
			w, err = zcash.NewZCashWallet(coin, cfg.Mnemonic, cfg.Params, cfg.Proxy, cfg.Cache, cfg.DisableExchangeRates)
			if err != nil {
				return nil, err
			}
			if cfg.Params.Name == chaincfg.MainNetParams.Name {
				multiwallet[util.ExtendCoinType(wallet.Zcash)] = w
			} else {
				multiwallet[util.ExtendCoinType(wallet.TestnetZcash)] = w
			}
		case util.ExtendCoinType(wallet.Litecoin):
			w, err = litecoin.NewLitecoinWallet(coin, cfg.Mnemonic, cfg.Params, cfg.Proxy, cfg.Cache, cfg.DisableExchangeRates)
			if err != nil {
				return nil, err
			}
			if cfg.Params.Name == chaincfg.MainNetParams.Name {
				multiwallet[util.ExtendCoinType(wallet.Litecoin)] = w
			} else {
				multiwallet[util.ExtendCoinType(wallet.TestnetLitecoin)] = w
			}
		case util.ExtendCoinType(wallet.Ethereum):
			w, err = eth.NewEthereumWallet(coin, cfg.Params, cfg.Mnemonic, cfg.Proxy)
			if err != nil {
				return nil, err
			}
			if cfg.Params.Name == chaincfg.MainNetParams.Name {
				multiwallet[util.ExtendCoinType(wallet.Ethereum)] = w
			} else {
				multiwallet[util.ExtendCoinType(wallet.TestnetEthereum)] = w
			}
		}
	}
	return multiwallet, nil
}

func (w *MultiWallet) Start() {
	for _, wallet := range *w {
		wallet.Start()
	}
}

func (w *MultiWallet) Close() {
	for _, wallet := range *w {
		wallet.Close()
	}
}

func (w *MultiWallet) WalletForCurrencyCode(currencyCode string) (wallet.Wallet, error) {
	for _, wl := range *w {
		if strings.EqualFold(wl.CurrencyCode(), currencyCode) || strings.EqualFold(wl.CurrencyCode(), "T"+currencyCode) {
			return wl, nil
		}
	}
	return nil, UnsuppertedCoinError
}
