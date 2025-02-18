/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/nats-io/nats-server/v2/examples/centralized/app/root"
	"github.com/nats-io/nats-server/v2/examples/internal"
	"github.com/rs/zerolog"
)

func main() {

	rootCommand := root.InitRootCmd()
	ctx := context.Background()
	logz := zerolog.New(os.Stdout).With().Caller().Timestamp().Logger()
	ctx = logz.WithContext(ctx)
	internal.SetContext(ctx)
	err := root.ExecuteE(rootCommand)
	if err != nil {
		fmt.Println(err)
	}
}
