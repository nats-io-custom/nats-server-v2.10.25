package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	status "github.com/gogo/status"
	"github.com/nats-io/nats-server/v2/examples/internal"
	"github.com/nats-io/nats-server/v2/examples/internal/cobra_utils"
	nats "github.com/nats-io/nats.go"
	nkeys "github.com/nats-io/nkeys"
	zerolog "github.com/rs/zerolog"
	cobra "github.com/spf13/cobra"
	viper "github.com/spf13/viper"
	codes "google.golang.org/grpc/codes"
)

const use = "service"

type Inputs struct {
	NatsUrl   string `json:"natsUrl"`
	IssuerKey string `json:"signerKey"`
	XKey      string `json:"xKey"`
}
type (
	RawKeyPair struct {
		PublicKey  string `json:"public_key"`
		PrivateKey []byte `json:"private_key"`
		Seed       []byte `json:"seed"`
	}
	CommonAccountData struct {
		Name string `json:"name"`
		JWT  string `json:"jwt"`
	}
	UpdateSimpleAccountRequest struct {
		Original      *CommonAccountData `json:"original"`
		IssuerKeyPair nkeys.KeyPair      `json:"issuer_key_pair"`
	}
)

var (
	appInputs = &Inputs{
		NatsUrl:   nats.DefaultURL,
		IssuerKey: "SAAEXFSYMLINXLKR2TG5FLHCJHLU62B3SK3ESZLGP4B4XGLUNXICW3LGAY",
		XKey:      "XCND2ELXRACFDAD7CFHXHZE7QPSEHW5IKNLPM5Y2FVFS7PHU6NUDMHKR",
	}
)

type AccountInfo struct {
	JWT          string        `json:"jwt"`
	FriendlyName string        `json:"friendlyName"`
	PublicKey    string        `json:"publicKey"`
	KeyPair      nkeys.KeyPair `json:"keyPair"`
}

// will be in a persistent store
var accountFriendlyNameToAccountInfo = make(map[string]*AccountInfo)
var accountPubKeyToAccountInfo = make(map[string]*AccountInfo)

// Init command
func Init(parentCmd *cobra.Command) {
	var command = &cobra.Command{
		Use:               use,
		Short:             use,
		PersistentPreRunE: cobra_utils.ParentPersistentPreRunE,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := internal.GetContext()
			log := zerolog.Ctx(ctx).With().Str("command", use).Logger()

			// Parse the issuer account signing key.
			issuerKeyPair, err := nkeys.FromSeed([]byte(appInputs.IssuerKey))
			if err != nil {
				log.Error().Err(err).Msg("error parsing issuer seed")
				return status.Error(codes.Internal, "error parsing issuer seed")
			}
			// Parse the xkey seed if present.
			var curveKeyPair nkeys.KeyPair
			if len(appInputs.XKey) > 0 {
				curveKeyPair, err = nkeys.FromSeed([]byte(appInputs.XKey))
				if err != nil {
					log.Error().Err(err).Msg("error parsing xkey seed")
					return status.Error(codes.Internal, "error parsing xkey seed")
				}
			}
			return nil
		},
	}
	flagName := "nats.url"
	defaultS := appInputs.NatsUrl
	command.Flags().StringVar(&appInputs.NatsUrl, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	flagName = "issuer.key"
	defaultS = appInputs.IssuerKey
	command.Flags().StringVar(&appInputs.IssuerKey, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	flagName = "x.key"
	defaultS = appInputs.XKey
	command.Flags().StringVar(&appInputs.XKey, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	parentCmd.AddCommand(command)

}

var accountMap = sync.Map{}
var accountNameToPublicKeyMap = sync.Map{}
var accountLock = sync.Mutex{}

func tryFetchFriendlyAccountPublicKey(accountPublicKey string) (string, bool) {
	accountLock.Lock()
	defer accountLock.Unlock()
	val, ok := accountNameToPublicKeyMap.Load(accountPublicKey)
	if ok {
		return val.(string), true
	}
	return "", false
}
func getOrCreateAccount(ctx context.Context, friendlyAccountName string) (*CommonAccountData, error) {
	accountLock.Lock()
	defer accountLock.Unlock()
	val, ok := accountMap.Load(friendlyAccountName)
	if ok {
		resp, err := configurator_shared.UpdateSimpleAccount(ctx, &UpdateSimpleAccountRequest{
			Original:      val.(*models.CreateSimpleAccountResponse),
			IssuerKeyPair: issuerKeyPair,
		})
		if err != nil {
			return nil, err
		}
		accountMap.Store(friendlyAccountName, resp)
		accountNameToPublicKeyMap.Store(resp.KeyPair.PublicKey, friendlyAccountName)
		return resp, nil
	}
	resp, err := configurator_shared.CreateSimpleAccount(ctx,
		&models.CreateSimpleAccountRequest{
			Name:          friendlyAccountName,
			IssuerKeyPair: issuerKeyPair,
		})
	if err != nil {
		return nil, err
	}
	accountMap.Store(friendlyAccountName, resp)
	accountNameToPublicKeyMap.Store(resp.KeyPair.PublicKey, friendlyAccountName)
	return resp, nil
}

func loadAndParseKeys(fp string, kind byte) (nkeys.KeyPair, error) {
	if fp == "" {
		return nil, errors.New("key file required")
	}
	seed, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("error reading key file: %w", err)
	}
	if !bytes.HasPrefix(seed, []byte{'S', kind}) {
		return nil, fmt.Errorf("key must be a private key")
	}
	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("error parsing key: %w", err)
	}
	return kp, nil
}

func getConnectionOptions(fp string) ([]nats.Option, error) {
	if fp == "" {
		return nil, errors.New("creds file required")
	}
	return []nats.Option{nats.UserCredentials(fp)}, nil
}

func UpdateAccount(nc *nats.Conn, token string) (*ResolverUpdateResponse, error) {
	var r ResolverUpdateResponse
	m, err := nc.Request("$SYS.REQ.CLAIMS.UPDATE", []byte(token), time.Second*2)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(m.Data, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

type UpdateData struct {
	Account string `json:"account"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ResolverResponse struct {
	Error  *ErrorDetails `json:"error,omitempty"`
	Server ServerDetails `json:"server"`
}

type ServerDetails struct {
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	ID        string    `json:"id"`
	Version   string    `json:"ver"`
	Jetstream bool      `json:"jetstream"`
	Flags     int       `json:"flags"`
	Sequence  int       `json:"seq"`
	Time      time.Time `json:"time"`
}

type ErrorDetails struct {
	Account     string `json:"account"`
	Code        int    `json:"code"`
	Description string `json:"description"`
}

type ResolverUpdateResponse struct {
	ResolverResponse
	UpdateData UpdateData `json:"data"`
}
