package centralized

import (
	"github.com/nats-io/nats-server/v2/examples/centralized/app/root/callout/centralized/service"
	"github.com/nats-io/nats-server/v2/examples/internal/cobra_utils"
	cobra "github.com/spf13/cobra"
)

const use = "centralized"

// Init command
func Init(parentCmd *cobra.Command) {
	var command = &cobra.Command{
		Use:               use,
		Short:             use,
		PersistentPreRunE: cobra_utils.ParentPersistentPreRunE,
	}

	parentCmd.AddCommand(command)

	service.Init(command)

}
