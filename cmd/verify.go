package cmd

import (
	"context"
	"fmt"
	"log"
	"maps"
	"os"
	"slices"

	"github.com/chris-cmsoft/concom/internal"
	"github.com/spf13/cobra"

	"github.com/adrg/xdg"
)

func VerifyCmd() *cobra.Command {
	var verifyCmd = &cobra.Command{
		Use:   "verify",
		Short: "Verify policies for cf",
		Long: `Policies in Compliance Framework require some metadata such as controls or policy_ids.
Verify ensures that all required metadata is set before the policies are uploaded to an OCI registry`,
		Run: VerifyPolicies,
	}

	verifyCmd.Flags().StringP("policy-path", "p", "", "Directory where policies are stored")
	err := verifyCmd.MarkFlagDirname("policy-path")
	if err != nil {
		log.Fatalf("Error marking policy-path for dirname completion: %v", err)
	}

	return verifyCmd
}

func VerifyPolicies(cmd *cobra.Command, args []string) {
	configFilePath, err := xdg.SearchConfigFile("concom/agent.yaml")
	if err != nil {
		configFiles := []string{fmt.Sprintf("%s/concom/agent.yaml", xdg.ConfigHome)}
		for _, dir := range xdg.ConfigDirs {
			configFiles = append(configFiles, fmt.Sprintf("%s/concom/agent.yaml", dir))
		}
		log.Println("No config file found at locations:", configFiles)
	} else {
		log.Println("Using config file at:", configFilePath)
	}

	config, err := internal.ReadConfig(configFilePath)
	if err != nil {
		log.Fatal("Error reading config file", err)
	}

	policyPath, err := cmd.Flags().GetString("policy-path")
	if err != nil {
		log.Fatalf("Error reading policy-path flag: %v", err)
	}

	if policyPath == "" && config != nil {
		policyPath = config.PolicyPath
	}

	if policyPath == "" {
		log.Fatal("Policy path is required, please set in config file or CLI arguments")
	}

	log.Println("Policy path is:", policyPath)

	doVerifyPolicy(policyPath)
}

func doVerifyPolicy(policyPath string) {
	_, err := os.Stat(policyPath)
	internal.OnError(err, func(err error) {
		if os.IsNotExist(err) {
			log.Fatal("Policy path does not exist at specified policy-path")
		}
		log.Fatal(err)
	})

	ctx := context.TODO()
	compiler := internal.PolicyCompiler(ctx, policyPath)

	valid := true
	for _, module := range compiler.Modules {

		annotations := internal.ExtractAnnotations(module.Comments)
		if annotations["cf_enabled"] == nil {
			continue
		}
		if _, exists := annotations["cf_enabled"]; !exists {
			continue
		}
		if annotations["cf_enabled"] != true {
			continue
		}
		missingAnnotations := internal.SubtractSlice(internal.RequiredAnnotations, slices.Collect(maps.Keys(annotations)))
		if len(missingAnnotations) > 0 {
			log.Println(module.Package.Location.File, "is missing required annotations", missingAnnotations)
			valid = false
		}
	}

	if !valid {
		log.Fatal("Validation for Compliance Framework Policies failed")
	}

	log.Print("Validation for Compliance Framework Policies successful")
}
