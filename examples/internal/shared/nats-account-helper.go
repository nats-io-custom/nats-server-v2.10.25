package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	models "github.com/nats-io/nats-server/v2/examples/internal/models"
	utils "github.com/nats-io/nats-server/v2/examples/internal/utils"
	nats "github.com/nats-io/nats.go"
	nkeys "github.com/nats-io/nkeys"
	zerolog "github.com/rs/zerolog"
)

/*
	{
	  "jti": "HQ6INVX2LMI4NDXYZMN5U4L4J5TL42PLEWG3NBXUNH6L6IOQJXHA",
	  "iat": 1737755077,
	  "iss": "ODRSGJVWECSLUL4ZMJITH3TBTTU3M35IY37UXMQAFUD6N7DZ5XMCDIAG",
	  "name": "SYS",
	  "sub": "ADI67YVFPNBQ3HCNK3XRCFYKD2W2MN2KDHXRDKEMNUANPMTEGL35ZULD",
	  "nats": {
	    "exports": [
	      {
	        "name": "account-monitoring-streams",
	        "subject": "$SYS.ACCOUNT.*.>",
	        "type": "stream",
	        "account_token_position": 3,
	        "description": "Account specific monitoring stream",
	        "info_url": "https://docs.nats.io/nats-server/configuration/sys_accounts"
	      },
	      {
	        "name": "account-monitoring-services",
	        "subject": "$SYS.REQ.ACCOUNT.*.*",
	        "type": "service",
	        "response_type": "Stream",
	        "account_token_position": 4,
	        "description": "Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO",
	        "info_url": "https://docs.nats.io/nats-server/configuration/sys_accounts"
	      }
	    ],
	    "limits": {
	      "subs": -1,
	      "data": -1,
	      "payload": -1,
	      "imports": -1,
	      "exports": -1,
	      "wildcards": true,
	      "conn": -1,
	      "leaf": -1
	    },
	    "signing_keys": [
	      "AAILKV6P4MK3M7IMU26Q2HTYQNEWOUNPGOZXOCF4KPLFDOSM7QH4PSGU"
	    ],
	    "default_permissions": {
	      "pub": {},
	      "sub": {}
	    },
	    "authorization": {},
	    "type": "account",
	    "version": 2
	  }
	}
*/
func CreateSystemAccount(ctx context.Context, request *models.CreateSystemAccountRequest) (*models.CreateSystemAccountResponse, error) {
	log := zerolog.Ctx(ctx).With().Str("func", "CreateSystemAccount").Logger()
	// create an account keypair
	akp, err := nkeys.CreateAccount()
	if err != nil {
		log.Error().Err(err).Msg("failed to create account")
		return nil, err
	}
	// extract the public key for the account
	apk, err := akp.PublicKey()
	if err != nil {
		log.Error().Err(err).Msg("failed to get public key")
		return nil, err
	}

	// create the claim for the account using the public key of the account
	ac := jwt.NewAccountClaims(apk)
	ac.Name = request.Name
	// create a signing key that we can use for issuing users
	askp, err := nkeys.CreateAccount()
	if err != nil {
		log.Error().Err(err).Msg("failed to create account")
		return nil, err
	}
	// extract the public key
	aspk, err := askp.PublicKey()
	if err != nil {
		log.Error().Err(err).Msg("failed to get public key")
		return nil, err
	}
	// add the signing key (public) to the account
	ac.SigningKeys.Add(aspk)

	ac.Exports.Add(&jwt.Export{
		Info: jwt.Info{
			Description: "Account specific monitoring stream",
			InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
		},
		Name:                 "account-monitoring-streams",
		Subject:              "$SYS.ACCOUNT.*.>",
		Type:                 jwt.Stream,
		AccountTokenPosition: 3,
	}, &jwt.Export{
		Info: jwt.Info{
			Description: "Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO",

			InfoURL: "https://docs.nats.io/nats-server/configuration/sys_accounts",
		},
		Name:                 "account-monitoring-services",
		Subject:              "$SYS.REQ.ACCOUNT.*.*",
		Type:                 jwt.Service,
		ResponseType:         jwt.ResponseTypeStream,
		AccountTokenPosition: 4,
	})
	// now we could encode an issue the account using the operator
	// key that we generated above, but this will illustrate that
	// the account could be self-signed, and given to the operator
	// who can then re-sign it
	accountJWT, err := ac.Encode(request.IssuerKeyPair)
	if err != nil {
		log.Error().Err(err).Msg("failed to encode account")
		return nil, err
	}

	resp := &models.CreateSystemAccountResponse{
		CommonAccountData: models.CommonAccountData{
			Name: request.Name,
			JWT:  accountJWT,
		},
	}
	resp.KeyPair.PublicKey, _ = akp.PublicKey()
	resp.KeyPair.PrivateKey, _ = akp.PrivateKey()
	resp.KeyPair.Seed, _ = akp.Seed()
	resp.SignerKeyPair.PublicKey, _ = askp.PublicKey()
	resp.SignerKeyPair.PrivateKey, _ = askp.PrivateKey()
	resp.SignerKeyPair.Seed, _ = askp.Seed()

	// generate a creds formatted file that can be used by a NATS client
	createUserCredsResponse, err := CreateUserWithCreds(ctx, &models.CreateUserWithCredsRequest{
		IssuerID:      apk,
		SignerKeyPair: askp,
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to format user config")
		return nil, err
	}
	resp.AccountUser = createUserCredsResponse
	return resp, nil
}
func randomInt64(min, max int64) int64 {
	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())
	// Generate a random number in the range [min, max]
	return min + rand.Int63n(max-min+1)
}

// a POC for updating an account
func UpdateSimpleAccount(ctx context.Context, request *models.UpdateSimpleAccountRequest) (*models.CreateSimpleAccountResponse, error) {
	log := zerolog.Ctx(ctx).With().Str("func", "UpdateSimpleAccount").Logger()
	akp, _ := nkeys.FromSeed(request.Original.KeyPair.Seed)
	apk, _ := akp.PublicKey()
	askp, _ := nkeys.FromSeed(request.Original.SignerKeyPair.Seed)
	// extract the public key
	aspk, err := askp.PublicKey()
	if err != nil {
		log.Error().Err(err).Msg("failed to get public key")
		return nil, err
	}

	// create the claim for the account using the public key of the account
	ac := jwt.NewAccountClaims(apk)
	ac.Name = request.Original.Name
	// create a random int64 between 1000000000 and 2000000000
	randomNum := randomInt64(1000000000, 2000000000)
	ac.Limits.JetStreamLimits.DiskStorage = randomNum
	ac.Limits.JetStreamLimits.MemoryStorage = randomNum

	ac.Expires = time.Now().Add(time.Minute * 2).Unix()

	// add the signing key (public) to the account
	ac.SigningKeys.Add(aspk)

	// now we could encode an issue the account using the operator
	// key that we generated above, but this will illustrate that
	// the account could be self-signed, and given to the operator
	// who can then re-sign it
	accountJWT, err := ac.Encode(request.IssuerKeyPair)
	if err != nil {
		log.Error().Err(err).Msg("failed to encode account")
		return nil, err
	}
	request.Original.JWT = accountJWT

	return request.Original, nil
}
func CreateSimpleAccount(ctx context.Context, request *models.CreateSimpleAccountRequest) (*models.CreateSimpleAccountResponse, error) {
	log := zerolog.Ctx(ctx).With().Str("func", "CreateSimpleAccount").Logger()
	// create an account keypair
	akp, err := nkeys.CreateAccount()
	if err != nil {
		log.Error().Err(err).Msg("failed to create account")
		return nil, err
	}

	// extract the public key for the account
	apk, err := akp.PublicKey()
	if err != nil {
		log.Error().Err(err).Msg("failed to get public key")
		return nil, err
	}
	// create a signing key that we can use for issuing users
	askp, err := nkeys.CreateAccount()
	if err != nil {
		log.Error().Err(err).Msg("failed to create account")
		return nil, err
	}
	// extract the public key
	aspk, err := askp.PublicKey()
	if err != nil {
		log.Error().Err(err).Msg("failed to get public key")
		return nil, err
	}
	// create the claim for the account using the public key of the account
	ac := jwt.NewAccountClaims(apk)
	ac.Name = request.Name
	ac.Expires = time.Now().Add(time.Minute * 2).Unix()
	ac.Limits.JetStreamLimits.DiskStorage = -1
	ac.Limits.JetStreamLimits.MemoryStorage = -1

	// add the signing key (public) to the account
	ac.SigningKeys.Add(aspk)

	// now we could encode an issue the account using the operator
	// key that we generated above, but this will illustrate that
	// the account could be self-signed, and given to the operator
	// who can then re-sign it
	accountJWT, err := ac.Encode(request.IssuerKeyPair)
	if err != nil {
		log.Error().Err(err).Msg("failed to encode account")
		return nil, err
	}

	// this user is our sentinel user that has no rights but lets us pass username/password where password can be our opaque token
	createSentinelUserCredsResponse, err := CreateUserWithCreds(ctx,
		&models.CreateUserWithCredsRequest{
			Name:          "sentinel",
			IssuerID:      apk,
			SignerKeyPair: askp,
			Permissions: jwt.Permissions{
				Pub: jwt.Permission{
					Deny: []string{">"},
				},
				Sub: jwt.Permission{
					Deny: []string{">"},
				},
			},
		})
	if err != nil {
		log.Error().Err(err).Msg("failed to create sentinel creds")
		return nil, err
	}

	resp := &models.CreateSimpleAccountResponse{
		CommonAccountData: models.CommonAccountData{
			Name: request.Name,
			JWT:  accountJWT,
		},
	}
	resp.KeyPair.PublicKey, _ = akp.PublicKey()
	resp.KeyPair.PrivateKey, _ = akp.PrivateKey()
	resp.KeyPair.Seed, _ = akp.Seed()
	resp.SignerKeyPair.PublicKey, _ = askp.PublicKey()
	resp.SignerKeyPair.PrivateKey, _ = askp.PrivateKey()
	resp.SignerKeyPair.Seed, _ = askp.Seed()
	resp.SentinelUser = createSentinelUserCredsResponse
	return resp, nil
}
func CreateAuthAccount(ctx context.Context, request *models.CreateAuthAccountRequest) (*models.CreateAuthAccountResponse, error) {
	log := zerolog.Ctx(ctx).With().Str("func", "CreateAuthAccount").Logger()
	// create an account keypair
	rootAccount, err := nkeys.CreateAccount()
	if err != nil {
		log.Error().Err(err).Msg("failed to create account")
		return nil, err
	}
	// extract the public key for the account
	rootAccountPublicKey, err := rootAccount.PublicKey()
	if err != nil {
		log.Error().Err(err).Msg("failed to get public key")
		return nil, err
	}
	// generate a creds formatted file that can be used by a NATS client

	// create the claim for the account using the public key of the account
	ac := jwt.NewAccountClaims(rootAccountPublicKey)
	ac.Name = request.Name
	// create a signing key that we can use for issuing users
	signerAccount, err := nkeys.CreateAccount()
	if err != nil {
		log.Error().Err(err).Msg("failed to create account")
		return nil, err
	}
	// extract the public key
	signerAccountPublicKey, err := signerAccount.PublicKey()
	if err != nil {
		log.Error().Err(err).Msg("failed to get public key")
		return nil, err
	}
	// this user is to allow the callout service to connect and register the micro api
	createUserCredsResponse, err := CreateUserWithCreds(ctx,
		&models.CreateUserWithCredsRequest{
			Name:          "auth",
			IssuerID:      rootAccountPublicKey,
			SignerKeyPair: signerAccount,
		})
	if err != nil {
		log.Error().Err(err).Msg("failed to format user config")
		return nil, err
	}

	// this user is our sentinel user that has no rights but lets us pass username/password where password can be our opaque token
	createSentinelUserCredsResponse, err := CreateUserWithCreds(ctx,
		&models.CreateUserWithCredsRequest{
			Name:          "sentinel",
			IssuerID:      rootAccountPublicKey,
			SignerKeyPair: signerAccount,
			Permissions: jwt.Permissions{
				Pub: jwt.Permission{
					Deny: []string{">"},
				},
				Sub: jwt.Permission{
					Deny: []string{">"},
				},
			},
		})
	if err != nil {
		log.Error().Err(err).Msg("failed to create sentinel creds")
		return nil, err
	}

	// add the signing key (public) to the account
	operatorPublicKey, _ := request.IssuerKeyPair.PublicKey()
	ac.SigningKeys.Add(signerAccountPublicKey, operatorPublicKey)
	// don't know about this one.
	ac.Authorization.AuthUsers.Add(createUserCredsResponse.UserKeyPair.PublicKey)
	ac.Authorization.AllowedAccounts.Add("*")
	ac.Limits.DiskStorage = -1
	ac.Limits.MemoryStorage = -1
	//ac.Limits.JetStreamLimits.DiskStorage = -1
	//ac.Limits.JetStreamLimits.MemoryStorage = -1
	// now we could encode an issue the account using the operator
	// key that we generated above, but this will illustrate that
	// the account could be self-signed, and given to the operator
	// who can then re-sign it
	accountJWT, err := ac.Encode(request.IssuerKeyPair)
	if err != nil {
		log.Error().Err(err).Msg("failed to encode account")
		return nil, err
	}

	resp := &models.CreateAuthAccountResponse{
		CommonAccountData: models.CommonAccountData{
			Name: request.Name,
			JWT:  accountJWT,
		},
	}
	resp.KeyPair.PublicKey, _ = rootAccount.PublicKey()
	resp.KeyPair.PrivateKey, _ = rootAccount.PrivateKey()
	resp.KeyPair.Seed, _ = rootAccount.Seed()
	resp.SignerKeyPair.PublicKey, _ = signerAccount.PublicKey()
	resp.SignerKeyPair.PrivateKey, _ = signerAccount.PrivateKey()
	resp.SignerKeyPair.Seed, _ = signerAccount.Seed()

	resp.AccountUser = createUserCredsResponse
	resp.SentinelUser = createSentinelUserCredsResponse
	return resp, nil
}

func CreateUserWithCreds(ctx context.Context, request *models.CreateUserWithCredsRequest) (*models.CreateUserWithCredsResonse, error) {
	log := zerolog.Ctx(ctx).With().Str("func", "CreateUserWithCreds").Logger()
	// now back to the account, the account can issue users
	// need not be known to the operator - the users are trusted
	// because they will be signed by the account. The server will
	// look up the account get a list of keys the account has and
	// verify that the user was issued by one of those keys
	ukp, err := nkeys.CreateUser()
	if err != nil {
		log.Error().Err(err).Msg("failed to create user")
		return nil, err
	}

	upk, err := ukp.PublicKey()
	if err != nil {
		log.Error().Err(err).Msg("failed to get public key")
		return nil, err
	}
	uc := jwt.NewUserClaims(upk)
	uc.Name = request.Name
	uc.Permissions = request.Permissions
	// ever expires

	// since the jwt will be issued by a signing key, the issuer account
	// must be set to the public ID of the account
	uc.IssuerAccount = request.IssuerID
	userJwt, err := uc.Encode(request.SignerKeyPair)
	if err != nil {
		log.Error().Err(err).Msg("failed to encode user")
		return nil, err
	}
	// the seed is a version of the keypair that is stored as text
	useed, err := ukp.Seed()
	if err != nil {
		log.Error().Err(err).Msg("failed to get seed")
		return nil, err
	}
	// generate a creds formatted file that can be used by a NATS client
	creds, err := jwt.FormatUserConfig(userJwt, useed)
	if err != nil {
		log.Error().Err(err).Msg("failed to format user config")
		return nil, err
	}
	privKey, _ := ukp.PrivateKey()
	return &models.CreateUserWithCredsResonse{
		UserKeyPair: models.RawKeyPair{
			PublicKey:  upk,
			PrivateKey: privKey,
			Seed:       useed,
		},
		JWT:   userJwt,
		Creds: creds,
	}, nil
}

/*
	{
	  "jti": "X53WBIL2MXEZZ2R6WVGKTWHZ3ENVRNTTYBLWEJJSQFQHKBQWUVGA",
	  "iat": 1737755087,
	  "iss": "OCQGZZVCJGGNR65Y72L6CNBRBHSZ7OILNQAXZLBZRAJUTDOA5JABBGWP",
	  "name": "local-callout-resolver2",
	  "sub": "OCQGZZVCJGGNR65Y72L6CNBRBHSZ7OILNQAXZLBZRAJUTDOA5JABBGWP",
	  "nats": {
	    "signing_keys": [
	      "ODRSGJVWECSLUL4ZMJITH3TBTTU3M35IY37UXMQAFUD6N7DZ5XMCDIAG"
	    ],
	    "account_server_url": "nats://localhost:4222",
	    "system_account": "ADI67YVFPNBQ3HCNK3XRCFYKD2W2MN2KDHXRDKEMNUANPMTEGL35ZULD",
	    "strict_signing_key_usage": true,
	    "type": "operator",
	    "version": 2
	  }
	}
*/
func CreateOperator(ctx context.Context, request *models.CreateOperatorRequest) (*models.CreateOperatorResponse, error) {
	log := zerolog.Ctx(ctx).With().Str("func", "CreateOperator").Logger()
	// create an operator key pair (private key)
	rootOperator, err := nkeys.CreateOperator()
	if err != nil {
		log.Error().Err(err).Msg("failed to create operator")
		return nil, err
	}

	// extract the public key
	rootOperatorPublicKey, err := rootOperator.PublicKey()
	if err != nil {
		log.Error().Err(err).Msg("failed to get public key")
		return nil, err
	}
	// create an operator claim using the public key for the identifier
	oc := jwt.NewOperatorClaims(rootOperatorPublicKey)
	oc.Name = request.Name
	oc.StrictSigningKeyUsage = true
	// add an operator signing key to sign accounts
	signerOperator, err := nkeys.CreateOperator()
	if err != nil {
		log.Error().Err(err).Msg("failed to create operator")
		return nil, err
	}
	// get the public key for the signing key
	signerOperatorPublicKey, err := signerOperator.PublicKey()
	if err != nil {
		log.Error().Err(err).Msg("failed to get public key")
		return nil, err
	}
	oc.SigningKeys.Add(signerOperatorPublicKey, rootOperatorPublicKey)
	// self-sign the operator JWT - the operator trusts itself
	operatorJWT, err := oc.Encode(rootOperator)
	if err != nil {
		log.Error().Err(err).Msg("failed to encode operator")
		return nil, err
	}

	createSystemAccountResponse, err := CreateSystemAccount(ctx, &models.CreateSystemAccountRequest{
		CreateSimpleAccountRequest: models.CreateSimpleAccountRequest{
			Name:          "SYS",
			IssuerKeyPair: signerOperator,
		},
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to create system account")
		return nil, err
	}
	oc.SystemAccount = createSystemAccountResponse.KeyPair.PublicKey

	createAuthAccountResponse, err := CreateAuthAccount(ctx, &models.CreateAuthAccountRequest{
		Name:          "AUTH",
		IssuerKeyPair: signerOperator,
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to create auth account")
		return nil, err
	}

	resp := &models.CreateOperatorResponse{
		OperatorAccount: models.CommonAccountData{
			Name: request.Name,
			JWT:  operatorJWT,
		},
	}
	resp.OperatorAccount.KeyPair.PublicKey, _ = rootOperator.PublicKey()
	resp.OperatorAccount.KeyPair.PrivateKey, _ = rootOperator.PrivateKey()
	resp.OperatorAccount.KeyPair.Seed, _ = rootOperator.Seed()
	resp.OperatorAccount.SignerKeyPair.PublicKey, _ = signerOperator.PublicKey()
	resp.OperatorAccount.SignerKeyPair.PrivateKey, _ = signerOperator.PrivateKey()
	resp.OperatorAccount.SignerKeyPair.Seed, _ = signerOperator.Seed()
	resp.SystemAccount = createSystemAccountResponse
	resp.AuthAccount = createAuthAccountResponse
	return resp, nil

}
func EnsureOutputFolder(ctx context.Context, rootFolder string) (string, error) {
	log := zerolog.Ctx(ctx).With().Str("func", "WriteNatsSystemAccountCreds").Logger()
	exePath, err := os.Executable()
	if err != nil {
		log.Error().Err(err).Msg("failed to get executable path")
		return "", err
	}

	exeDir := filepath.Dir(exePath)
	outDir := path.Join(exeDir, rootFolder)
	err = os.MkdirAll(outDir, 0755) // 0755 permissions are typical (read/write/execute for owner, read/execute for group and others)
	if err != nil {
		log.Error().Err(err).Msg("failed to create directory")
		return "", err
	}
	return outDir, nil
}
func WriteCreds(ctx context.Context, outDir string, request *models.WriteCredsRequest) (*models.WriteCredsResponse, error) {
	log := zerolog.Ctx(ctx).With().Str("func", "WriteNatsSystemAccountCreds").Logger()

	credsPath := path.Join(outDir, fmt.Sprintf("%s.creds", request.Name))
	if err := os.WriteFile(credsPath,
		request.Creds, 0644); err != nil {
		log.Error().Err(err).Msg("failed to write creds")
		return nil, err

	}
	return &models.WriteCredsResponse{
		CredsFile: credsPath,
	}, nil
}
func WriteNatsSystemAccountCreds(ctx context.Context, outDir string, createOperatorResponse *models.CreateOperatorResponse) error {
	log := zerolog.Ctx(ctx).With().Str("func", "WriteNatsSystemAccountCreds").Logger()
	ctx = log.WithContext(ctx)
	_, err := WriteCreds(ctx, outDir, &models.WriteCredsRequest{
		Name:  "sys",
		Creds: createOperatorResponse.SystemAccount.AccountUser.Creds,
	})
	return err

}
func WriteNatsAuthAccountCreds(ctx context.Context, outDir string, createOperatorResponse *models.CreateOperatorResponse) error {
	log := zerolog.Ctx(ctx).With().Str("func", "WriteNatsAuthAccountCreds").Logger()
	ctx = log.WithContext(ctx)
	_, err := WriteCreds(ctx, outDir, &models.WriteCredsRequest{
		Name:  "callout.account",
		Creds: createOperatorResponse.AuthAccount.AccountUser.Creds,
	})
	if err != nil {
		return err
	}
	_, err = WriteCreds(ctx, outDir, &models.WriteCredsRequest{
		Name:  "callout.sentinel",
		Creds: createOperatorResponse.AuthAccount.SentinelUser.Creds,
	})
	return err
}

func WriteNatsServerConfig(ctx context.Context, outDir string, createOperatorResponse *models.CreateOperatorResponse) error {
	log := zerolog.Ctx(ctx).With().Str("func", "WriteNatsServerConfig").Logger()

	natsConfPath := path.Join(outDir, "server.conf")
	// we are generating a memory resolver server configuration
	// it lists the operator and all account jwts the server should
	// know about
	resolver := fmt.Sprintf(
		`# Operator named %s
operator: %s
# System Account named SYS
system_account: %s

# configuration of the nats based resolver
resolver {
    type: full
    # Directory in which account jwt will be stored
    dir: './jwt'
    # In order to support jwt deletion, set to true
    # If the resolver type is full delete will rename the jwt.
    # This is to allow manual restoration in case of inadvertent deletion.
    # To restore a jwt, remove the added suffix .delete and restart or send a reload signal.
    # To free up storage you must manually delete files with the suffix .delete.
    allow_delete: false
    # Interval at which a nats-server with a nats based account resolver will compare
    # it's state with one random nats based account resolver in the cluster and if needed,
    # exchange jwt and converge on the same set of jwt.
    interval: "2m"
	# limit on the number of jwt stored, will reject new jwt once limit is hit.
    limit: 1000000
}
# Preload the nats based resolver with the system account jwt.
# This is not necessary but avoids a bootstrapping system account. 
# This only applies to the system account. Therefore other account jwt are not included here.
# To populate the resolver:
# 1) make sure that your operator has the account server URL pointing at your nats servers.
#    The url must start with: "nats://" 
#    nsc edit operator --account-jwt-server-url nats://localhost:4222
# 2) push your accounts using: nsc push --all
#    The argument to push -u is optional if your account server url is set as described.
# 3) to prune accounts use: nsc push --prune 
#    In order to enable prune you must set above allow_delete to true
# Later changes to the system account take precedence over the system account jwt listed here.
resolver_preload: {
    %s: %s
}
`,
		createOperatorResponse.OperatorAccount.Name,
		createOperatorResponse.OperatorAccount.JWT,
		createOperatorResponse.SystemAccount.KeyPair.PublicKey,
		createOperatorResponse.SystemAccount.KeyPair.PublicKey,
		createOperatorResponse.SystemAccount.JWT,
	)
	if err := os.WriteFile(natsConfPath,
		[]byte(resolver), 0644); err != nil {
		log.Error().Err(err).Msg("failed to write resolver config")
		return err

	}
	return nil

}
func WriteMasterServiceConfig(ctx context.Context, outDir string, createOperatorResponse *models.CreateOperatorResponse) error {
	log := zerolog.Ctx(ctx).With().Str("func", "WriteMasterServiceConfig").Logger()

	natsConfPath := path.Join(outDir, "service.json")
	if err := os.WriteFile(natsConfPath,
		[]byte(utils.PrettyJSON(createOperatorResponse)), 0644); err != nil {
		log.Error().Err(err).Msg("failed to write resolver config")
		return err
	}
	return nil

}

func UpdateAccount(nc *nats.Conn, token string) (*models.ResolverUpdateResponse, error) {
	var r models.ResolverUpdateResponse
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

func NewAccountUserToken(accountUser *models.AccountUser) (string, error) {
	dd, err := json.Marshal(accountUser)
	if err != nil {
		return "", err
	}
	return string(dd), err

}
func DecodeAccountUserToken(token string) (*models.AccountUser, error) {
	var accountUser models.AccountUser
	err := json.Unmarshal([]byte(token), &accountUser)
	return &accountUser, err
}
