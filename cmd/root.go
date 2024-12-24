package cmd

import (
	"github.com/spf13/cobra"
	"github.com/szuwgh/pernis/common/vlog"
)

func getFlagString(command *cobra.Command, flag string) string {
	v, err := command.Flags().GetString(flag)
	if err != nil {
		vlog.Fatalln(err)
	}
	return v
}

func getFlagUint32(command *cobra.Command, flag string) uint32 {
	v, err := command.Flags().GetUint32(flag)
	if err != nil {
		vlog.Fatalln(err)
	}
	return v
}

func getFlagUint16(command *cobra.Command, flag string) uint16 {
	v, err := command.Flags().GetUint16(flag)
	if err != nil {
		vlog.Fatalln(err)
	}
	return v
}
