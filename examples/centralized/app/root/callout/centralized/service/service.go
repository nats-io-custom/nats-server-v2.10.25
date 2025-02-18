package service

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"

	status "github.com/gogo/status"
	jwt "github.com/nats-io/jwt/v2"
	internal "github.com/nats-io/nats-server/v2/examples/internal"
	cobra_utils "github.com/nats-io/nats-server/v2/examples/internal/cobra_utils"
	models "github.com/nats-io/nats-server/v2/examples/internal/models"
	shared "github.com/nats-io/nats-server/v2/examples/internal/shared"
	nats "github.com/nats-io/nats.go"
	micro "github.com/nats-io/nats.go/micro"
	nkeys "github.com/nats-io/nkeys"
	zerolog "github.com/rs/zerolog"
	cobra "github.com/spf13/cobra"
	viper "github.com/spf13/viper"
	codes "google.golang.org/grpc/codes"
)

const use = "service"

type Inputs struct {
	NATSUrl     string `json:"natsUrl"`
	IssuerKey   string `json:"signerKey"`
	XKey        string `json:"xKey"`
	CalloutUser string `json:"calloutUser"`
	CalloutPass string `json:"calloutPass"`
}

var (
	appInputs = &Inputs{
		NATSUrl:     nats.DefaultURL,
		IssuerKey:   "SAAEXFSYMLINXLKR2TG5FLHCJHLU62B3SK3ESZLGP4B4XGLUNXICW3LGAY",
		XKey:        "SXAMKSXEE3LCBT4NNMKGEDFRGGO4DDIPO5JQSPW6W5MHLZDMG6N2SKB2ZI",
		CalloutUser: "auth",
		CalloutPass: "auth",
	}
)

type AccountInfo struct {
	JWT          string        `json:"jwt"`
	FriendlyName string        `json:"friendlyName"`
	PublicKey    string        `json:"publicKey"`
	KeyPair      nkeys.KeyPair `json:"keyPair"`
}

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
			users := make(map[string]*models.User)
			sysAccount := "sys"
			users[sysAccount] = &models.User{
				Pass:    sysAccount,
				Account: "SYS",
				Permissions: jwt.Permissions{
					Pub: jwt.Permission{
						Allow: jwt.StringList{">"},
					},
					Sub: jwt.Permission{
						Allow: jwt.StringList{">"},
					},
				},
			}
			// Open the NATS connection passing the auth account creds file.
			nc, err := nats.Connect(appInputs.NATSUrl,
				nats.UserInfo(appInputs.CalloutUser, appInputs.CalloutPass))
			if err != nil {
				log.Error().Err(err).Msg("error connecting to NATS")
				return err
			}
			defer nc.Drain()

			// Helper function to construct an authorization response.
			respondMsg := func(req micro.Request, userNkey, serverId, userJwt, errMsg string) {
				rc := jwt.NewAuthorizationResponseClaims(userNkey)
				rc.Audience = serverId
				rc.Error = errMsg
				rc.Jwt = userJwt

				token, err := rc.Encode(issuerKeyPair)
				if err != nil {
					log.Error().Err(err).Msg("error encoding response JWT")
					req.Respond(nil)
					return
				}

				data := []byte(token)

				// Check if encryption is required.
				xkey := req.Headers().Get("Nats-Server-Xkey")
				if len(xkey) > 0 {
					data, err = curveKeyPair.Seal(data, xkey)
					if err != nil {
						log.Error().Err(err).Msg("error encrypting response")
						req.Respond(nil)
						return
					}
				}

				req.Respond(data)
			}
			// Define the message handler for the authorization request.
			msgHandler := func(req micro.Request) {
				var token []byte

				// Check for Xkey header and decrypt
				xkey := req.Headers().Get("Nats-Server-Xkey")
				if len(xkey) > 0 {
					if curveKeyPair == nil {
						respondMsg(req, "", "", "", "xkey not supported")
						return
					}

					// Decrypt the message.
					token, err = curveKeyPair.Open(req.Data(), xkey)
					if err != nil {
						respondMsg(req, "", "", "", "error decrypting message")
						return
					}
				} else {
					token = req.Data()
				}

				// Decode the authorization request claims.
				rc, err := jwt.DecodeAuthorizationRequestClaims(string(token))
				if err != nil {
					log.Error().Err(err).Msg("error decoding authorization request")
					respondMsg(req, "", "", "", err.Error())
					return
				}

				// Used for creating the auth response.
				userNkey := rc.UserNkey
				serverId := rc.Server.ID
				// Check if the user exists.
				accountUser, err := shared.DecodeAccountUserToken(rc.ConnectOptions.Token)
				if err != nil {
					// fail
					log.Error().Err(err).Msg("error decoding account user token")
					return
				}

				// check if this is the sys account
				userProfile, ok := users[accountUser.UserName]
				if !ok {
					// just create the user for the POC
					userProfile = &models.User{
						Pass:    accountUser.UserPassword,
						Account: accountUser.AccountName,
						Permissions: jwt.Permissions{
							Pub: jwt.Permission{
								Allow: jwt.StringList{">"},
							},
							Sub: jwt.Permission{
								Allow: jwt.StringList{">"},
							},
						},
					}
					users[accountUser.UserName] = userProfile
				}
				// Check if the credential is valid.
				if userProfile.Pass != accountUser.UserPassword {
					respondMsg(req, userNkey, serverId, "", "invalid credentials")
					return
				}

				// Prepare a user JWT.
				uc := jwt.NewUserClaims(rc.UserNkey)
				uc.Name = accountUser.UserName
				uc.Audience = userProfile.Account
				if uc.Name != sysAccount {
					//dd, _ := nkeys.Encode(nkeys.PrefixByteAccount, []byte(userProfile.Account))
					landingAccount, err := GetOrCreateAccount(ctx, &GetOrCreateAccountRequest{
						FriendlyAccountName: userProfile.Account,
						IssuerKeyPair:       issuerKeyPair,
					})
					if err != nil {
						respondMsg(req, userNkey, serverId, "", fmt.Sprintf("error getting account: %s", err))
						return
					}
					uc.Audience = landingAccount.KeyPair.PublicKey
				}
				// Check if signing key is associated, otherwise assume non-operator mode
				// and set the audience to the account.
				var sk nkeys.KeyPair
				sk = issuerKeyPair

				// Set the associated permissions if present.
				uc.Permissions = userProfile.Permissions

				// Validate the claims.
				vr := jwt.CreateValidationResults()
				uc.Validate(vr)
				if len(vr.Errors()) > 0 {
					respondMsg(req, userNkey, serverId, "", fmt.Sprintf("error validating claims: %s", vr.Errors()))
					return
				}

				// Sign it with the issuer key.
				ejwt, err := uc.Encode(sk)
				if err != nil {
					respondMsg(req, userNkey, serverId, "", fmt.Sprintf("error signing user JWT: %s", err))
					return
				}
				log.Info().Interface("accountUser", accountUser).Str("ejwt", ejwt).Msg("accountUser")
				respondMsg(req, userNkey, serverId, ejwt, "")
			}
			// Create a service for auth callout with an endpoint binding to
			// the required subject. This allows for running multiple instances
			// to distribute the load, observe stats, and provide high availability.
			srv, err := micro.AddService(nc, micro.Config{
				Name:        "auth-callout",
				Version:     "0.0.1",
				Description: "Auth callout service.",
			})
			if err != nil {
				return err
			}

			g := srv.
				AddGroup("$SYS").
				AddGroup("REQ").
				AddGroup("USER")

			err = g.AddEndpoint("AUTH", micro.HandlerFunc(msgHandler))
			if err != nil {
				return err
			}

			accountUserToken, err := shared.NewAccountUserToken(&models.AccountUser{
				AccountName:  "SYS",
				UserName:     sysAccount,
				UserPassword: sysAccount,
			})
			if err != nil {
				log.Error().Err(err).Msg("failed to create account user token")
				return err
			}

			opts := []nats.Option{}

			opts = append(opts, nats.Token(accountUserToken))

			ncSys, err := nats.Connect(appInputs.NATSUrl, opts...)
			if err != nil {
				log.Error().Err(err).Msg("failed to connect")
				return err
			}

			defer func() {
				defer ncSys.Drain()
			}()
			sub, err := ncSys.Subscribe("$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP", func(msg *nats.Msg) {
				accountId := strings.TrimSuffix(strings.TrimPrefix(msg.Subject, "$SYS.REQ.ACCOUNT."), ".CLAIMS.LOOKUP")

				friendlyName, ok := tryFetchFriendlyAccountPublicKey(accountId)
				if !ok {
					log.Error().Msgf("account not found: %s", accountId)
					return
				}
				createSimpleAccountResponse, err := GetOrCreateAccount(ctx, &GetOrCreateAccountRequest{
					FriendlyAccountName: friendlyName,
					IssuerKeyPair:       issuerKeyPair,
				})
				if err != nil {
					log.Error().Err(err).Msg("error getting account")
					return
				}
				createSimpleAccountResponse, err = shared.UpdateSimpleAccount(ctx, &models.UpdateSimpleAccountRequest{
					Original:      createSimpleAccountResponse,
					IssuerKeyPair: issuerKeyPair,
				})
				if err != nil {
					log.Error().Err(err).Msg("error getting account")
					return
				}
				jwt := createSimpleAccountResponse.JWT
				err = msg.Respond([]byte(jwt))
				if err != nil {
					log.Error().Err(err).Msg("error responding")
				}
				log.Info().Str("accountJWT", jwt).Msg("accountJWT")

			})
			if err != nil {
				log.Error().Err(err).Msg("error connecting to NATS")
				return err
			}
			defer func() {
				sub.Unsubscribe()
			}()
			log.Info().Msg("service started")

			// Block and wait for interrupt.
			sigch := make(chan os.Signal, 1)
			signal.Notify(sigch, os.Interrupt)
			<-sigch
			return nil
		},
	}
	flagName := "nats.url"
	defaultS := appInputs.NATSUrl
	command.Flags().StringVar(&appInputs.NATSUrl, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	flagName = "issuer.key"
	defaultS = appInputs.IssuerKey
	command.Flags().StringVar(&appInputs.IssuerKey, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	flagName = "x.key"
	defaultS = appInputs.XKey
	command.Flags().StringVar(&appInputs.XKey, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	flagName = "callout.user"
	defaultS = appInputs.CalloutUser
	command.Flags().StringVar(&appInputs.CalloutUser, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	flagName = "callout.pass"
	defaultS = appInputs.CalloutPass
	command.Flags().StringVar(&appInputs.CalloutPass, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
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

type GetOrCreateAccountRequest struct {
	FriendlyAccountName string
	IssuerKeyPair       nkeys.KeyPair
}

func GetOrCreateAccount(ctx context.Context, request *GetOrCreateAccountRequest) (*models.CreateSimpleAccountResponse, error) {
	accountLock.Lock()
	defer accountLock.Unlock()
	val, ok := accountMap.Load(request.FriendlyAccountName)
	if ok {
		resp, err := shared.UpdateSimpleAccount(ctx, &models.UpdateSimpleAccountRequest{
			Original:      val.(*models.CreateSimpleAccountResponse),
			IssuerKeyPair: request.IssuerKeyPair,
		})
		if err != nil {
			return nil, err
		}
		accountMap.Store(request.FriendlyAccountName, resp)
		accountNameToPublicKeyMap.Store(resp.KeyPair.PublicKey, request.FriendlyAccountName)
		return resp, nil
	}
	resp, err := shared.CreateSimpleAccount(ctx,
		&models.CreateSimpleAccountRequest{
			Name:          request.FriendlyAccountName,
			IssuerKeyPair: request.IssuerKeyPair,
		})
	if err != nil {
		return nil, err
	}
	accountMap.Store(request.FriendlyAccountName, resp)
	accountNameToPublicKeyMap.Store(resp.KeyPair.PublicKey, request.FriendlyAccountName)
	return resp, nil
}
