package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/tinkerer-labs/mft/internal/config"
)

func main() {
	fmt.Println("Started app mft")

	id, err := config.Load()
	if err != nil {
		log.Println("Generate public & private key error", err.Error())
		os.Exit(1)
	}
	slog.Info("App ID", slog.String("App ID", id.Identity.AppID))
}
