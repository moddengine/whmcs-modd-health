package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/moddengine/whmcs-modd-health/internal/health"
)

func main() {
	version := flag.Bool("version", false, "print version")
	validateConfig := flag.Bool("validate-config", false, "validate configuration JSON from stdin")
	flag.Parse()
	if *version {
		fmt.Println(health.Version)
		return
	}
	if *validateConfig {
		var config health.Configuration
		decoder := json.NewDecoder(os.Stdin)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			fatal(err)
		}
		if err := health.ValidateConfiguration(config); err != nil {
			fatal(err)
		}
		fmt.Println(`{"valid":true}`)
		return
	}
	job, err := health.DecodeJob(os.Stdin)
	if err != nil {
		fatal(err)
	}
	summary, runErr := health.Run(context.Background(), job)
	if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
		fatal(err)
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "modd_health:", runErr)
		os.Exit(1)
	}
}

func fatal(err error) {
	summary := health.Summary{Error: err.Error()}
	_ = json.NewEncoder(os.Stdout).Encode(summary)
	fmt.Fprintln(os.Stderr, "modd_health:", err)
	os.Exit(2)
}
