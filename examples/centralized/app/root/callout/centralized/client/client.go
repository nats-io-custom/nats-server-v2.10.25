package client

import (
	"fmt"
	"time"

	internal "github.com/nats-io/nats-server/v2/examples/internal"
	cobra_utils "github.com/nats-io/nats-server/v2/examples/internal/cobra_utils"
	models "github.com/nats-io/nats-server/v2/examples/internal/models"
	shared "github.com/nats-io/nats-server/v2/examples/internal/shared"
	nats "github.com/nats-io/nats.go"
	zerolog "github.com/rs/zerolog"
	cobra "github.com/spf13/cobra"
	viper "github.com/spf13/viper"
)

const use = "client"

type Inputs struct {
	NatsUrl      string `json:"natsUrl"`
	AccountName  string `json:"accountName"`
	UserName     string `json:"userName"`
	UserPassword string `json:"userPassword"`
}

var (
	appInputs = &Inputs{
		NatsUrl:      nats.DefaultURL,
		AccountName:  "golden",
		UserName:     "bob",
		UserPassword: "bob",
	}
)

// Init command
func Init(parentCmd *cobra.Command) {
	var command = &cobra.Command{
		Use:               use,
		Short:             use,
		PersistentPreRunE: cobra_utils.ParentPersistentPreRunE,
		RunE: func(cmd *cobra.Command, args []string) error {

			ctx := internal.GetContext()
			log := zerolog.Ctx(ctx).With().Str("command", use).Logger()

			accountUserToken, err := shared.NewAccountUserToken(&models.AccountUser{
				AccountName:  appInputs.AccountName,
				UserName:     appInputs.UserName,
				UserPassword: appInputs.UserPassword,
			})
			if err != nil {
				log.Error().Err(err).Msg("failed to create account user token")
				return err
			}
			// connect
			opts := []nats.Option{}

			opts = append(opts, nats.Token(accountUserToken))

			nc, err := nats.Connect(appInputs.NatsUrl, opts...)
			if err != nil {
				log.Error().Err(err).Msg("failed to connect")
				return err
			}
			defer nc.Close()

			// find out where we got placed
			r, err := nc.Request("$SYS.REQ.USER.INFO", nil, time.Second*2)
			if err != nil {
				log.Error().Err(err).Msg("failed to request")
				return err
			}
			fmt.Println(string(r.Data))

			return nil
		},
	}
	flagName := "nats.url"
	defaultS := appInputs.NatsUrl
	command.Flags().StringVar(&appInputs.NatsUrl, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	flagName = "account.name"
	defaultS = appInputs.AccountName
	command.Flags().StringVar(&appInputs.AccountName, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	flagName = "user.name"
	defaultS = appInputs.UserName
	command.Flags().StringVar(&appInputs.UserName, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	flagName = "user.password"
	defaultS = appInputs.UserPassword
	command.Flags().StringVar(&appInputs.UserPassword, flagName, defaultS, fmt.Sprintf("[required] i.e. --%s=%s", flagName, defaultS))
	viper.BindPFlag(flagName, command.PersistentFlags().Lookup(flagName))

	parentCmd.AddCommand(command)

}
