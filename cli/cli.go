package cli

import (
	"context"
	"os"

	"charm.land/fang/v2"

	"github.com/spf13/cobra"
)

type CLIResults struct {
	Domain   string
	Username string
	Password string
	NtlmHash string
	Kerberos bool
	Ldaps    bool
	Port     string
	ADCS     bool
	DC       string
}

func Run() (result CLIResults, err error) {
	cmd := &cobra.Command{
		Use:   "gohound [args]",
		Short: "golang bloodhound collector",
		Long:  "golang bloodhound collector made by Ceald!",

		Example: `
# Run it
gohound --domain "test.com" --dc "127.0.0.1" --ldaps --kerb --adcs --user "test" --password "test"
		`,
		Run: func(c *cobra.Command, args []string) {
			result.Username, _ = c.Flags().GetString("user")
			result.Password, _ = c.Flags().GetString("password")
			result.Kerberos, _ = c.Flags().GetBool("kerb")
			result.Ldaps, _ = c.Flags().GetBool("ldaps")
			result.ADCS, _ = c.Flags().GetBool("adcs")
			result.DC, _ = c.Flags().GetString("dc")
			result.NtlmHash, _ = c.Flags().GetString("hash")
			result.Port, _ = c.Flags().GetString("port")
			result.Domain, _ = c.Flags().GetString("domain")
		},
	}
	cmd.Flags().String("password", "", "")
	cmd.Flags().String("user", "", "")
	cmd.Flags().Bool("kerb", false, "")
	cmd.Flags().Bool("ldaps", false, "")
	cmd.Flags().Bool("adcs", false, "")
	cmd.Flags().String("dc", "127.0.0.1", "")
	cmd.Flags().String("hash", "", "")
	cmd.Flags().String("port", "389", "")
	cmd.Flags().String("domain", "", "")
	err = fang.Execute(context.Background(), cmd, fang.WithNotifySignal(os.Interrupt, os.Kill))
	return
}
