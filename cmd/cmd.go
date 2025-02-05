package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/szuwgh/pernis/common/vlog"
	"github.com/szuwgh/pernis/user"
)

const VERSION = "pernis version 0.1 linux/amd64"

var rootCmd = &cobra.Command{
	Use:   "pernis",
	Short: "go runtime simple monitor based on ebpf",
	Run: func(cmd *cobra.Command, args []string) {

	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show version",
	Run:   versionCommandFunc,
}

var rmcmd = &cobra.Command{
	Use:   "rm",
	Short: "show version",
	Run:   rmcmdFunc,
}

var listcmd = &cobra.Command{
	Use:   "list",
	Short: "show version",
	Run:   listcmdFunc,
}

// var tcpcmd = &cobra.Command{
// 	Use:   "tcp",
// 	Short: "show version",
// 	Run:   tcpcmdFunc,
// }

// var gotlscmd = &cobra.Command{
// 	Use:   "gotls",
// 	Short: "show version",
// 	Run:   tcpcmdFunc,
// }

var tlscmd = &cobra.Command{
	Use:   "tls",
	Short: "show version",
	Run:   tlscmdFunc,
}

var httpcmd = &cobra.Command{
	Use:   "http",
	Short: "show version",
	Run:   httpcmdFunc,
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(listcmd)
	rootCmd.AddCommand(tcCmd)
	rootCmd.AddCommand(rmcmd)
	//rootCmd.AddCommand(tcpcmd)
	rootCmd.AddCommand(tlscmd)
	rootCmd.AddCommand(httpcmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func listcmdFunc(command *cobra.Command, args []string) {
	vlog.Println("list filter")
	err := user.ListFilters("ens33")
	if err != nil {
		vlog.Println(err)
	}
}

func rmcmdFunc(command *cobra.Command, args []string) {
	vlog.Println("remove filter")
	err := user.RemoveTCFilters("ens33", user.DirectionToParent(user.DirEgress))
	if err != nil {
		vlog.Println(err)
	}
}

func versionCommandFunc(command *cobra.Command, args []string) {
	vlog.Println(VERSION)
	err := user.ObserveTC("ens33")
	if err != nil {
		vlog.Println(err)
	}
	select {}
}

func tlscmdFunc(command *cobra.Command, args []string) {
	vlog.Println("tls")
	err := user.AttachSSLUprobe()
	if err != nil {
		vlog.Println(err)
	}

}

// func tcpcmdFunc(command *cobra.Command, args []string) {
// 	vlog.Println("tcp")
// 	err := user.AttachTcpSendMsgKprobe()
// 	if err != nil {
// 		vlog.Println(err)
// 	}

// }

func httpcmdFunc(command *cobra.Command, args []string) {
	vlog.Println("http")
	err := user.AttachSysConnectKprobe()
	if err != nil {
		vlog.Println(err)
	}

}
