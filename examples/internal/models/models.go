package models

import (
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type (
	AccountUser struct {
		AccountName  string `json:"accountName"`
		UserName     string `json:"userName"`
		UserPassword string `json:"userPassword"`
	}
	User struct {
		Pass        string
		Account     string
		Permissions jwt.Permissions
	}
	ResolverResponse struct {
		Error  *ErrorDetails `json:"error,omitempty"`
		Server ServerDetails `json:"server"`
	}

	ServerDetails struct {
		Name      string    `json:"name"`
		Host      string    `json:"host"`
		ID        string    `json:"id"`
		Version   string    `json:"ver"`
		Jetstream bool      `json:"jetstream"`
		Flags     int       `json:"flags"`
		Sequence  int       `json:"seq"`
		Time      time.Time `json:"time"`
	}
	UpdateData struct {
		Account string `json:"account"`
		Code    int    `json:"code"`
		Message string `json:"message"`
	}

	ResolverUpdateResponse struct {
		ResolverResponse
		UpdateData UpdateData `json:"data"`
	}

	ErrorDetails struct {
		Account     string `json:"account"`
		Code        int    `json:"code"`
		Description string `json:"description"`
	}
	RawKeyPair struct {
		PublicKey  string `json:"public_key"`
		PrivateKey []byte `json:"private_key"`
		Seed       []byte `json:"seed"`
	}
	CommonAccountData struct {
		Name          string     `json:"name"`
		KeyPair       RawKeyPair `json:"key_pair"`
		SignerKeyPair RawKeyPair `json:"signer_key_pair"`
		JWT           string     `json:"jwt"`
	}
	CreateOperatorRequest struct {
		Name string `json:"name"`
	}
	CreateOperatorResponse struct {
		OperatorAccount CommonAccountData            `json:"operator_account"`
		SystemAccount   *CreateSystemAccountResponse `json:"system_account"`
		AuthAccount     *CreateAuthAccountResponse   `json:"auth_account"`
	}
	WriteCredsRequest struct {
		Name  string `json:"name"`
		Creds []byte `json:"creds"`
	}
	WriteCredsResponse struct {
		CredsFile string `json:"creds_file"`
	}

	CreateSimpleAccountRequest struct {
		Name          string        `json:"name"`
		IssuerKeyPair nkeys.KeyPair `json:"issuer_key_pair"`
	}
	CreateSimpleAccountResponse struct {
		CommonAccountData
		SentinelUser *CreateUserWithCredsResonse `json:"sentinel_user"`
	}

	UpdateSimpleAccountRequest struct {
		Original      *CreateSimpleAccountResponse `json:"original"`
		IssuerKeyPair nkeys.KeyPair                `json:"issuer_key_pair"`
	}
	CreateSystemAccountRequest struct {
		CreateSimpleAccountRequest
	}
	CreateSystemAccountResponse struct {
		CommonAccountData
		AccountUser *CreateUserWithCredsResonse `json:"account_user"`
	}
	CreateAuthAccountRequest struct {
		Name          string        `json:"name"`
		IssuerKeyPair nkeys.KeyPair `json:"issuer_key_pair"`
	}
	CreateAuthAccountResponse struct {
		CommonAccountData
		AccountUser  *CreateUserWithCredsResonse `json:"account_user"`
		SentinelUser *CreateUserWithCredsResonse `json:"sentinel_user"`
	}

	CreateUserWithCredsRequest struct {
		Name          string          `json:"name"`
		IssuerID      string          `json:"issuer_id"`
		SignerKeyPair nkeys.KeyPair   `json:"signer_key_pair"`
		Permissions   jwt.Permissions `json:"permissions"`
	}
	CreateUserWithCredsResonse struct {
		UserKeyPair RawKeyPair `json:"user_key_pair"`
		JWT         string     `json:"jwt"`
		Creds       []byte     `json:"creds"`
	}
)
