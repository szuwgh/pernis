package cmd

import (
	"github.com/spf13/cobra"
	"github.com/szuwgh/pernis/common/vlog"
	"github.com/szuwgh/pernis/user"
)

var Interface string

// vls tc
// vls tc -i ens33 init
// vls tc -i ens33 ip ls
// vls tc -i ens33 ls
// vls tc -i ens33 class ls
// vls tc -i ens33 class rm -c 1.8.4.8
// vls tc -i ens33 ip rm -ip 1.8.4.8
// vls tc -i ens33 ip add -c xx -ip 1.8.4.8
// vls tc -i ens33 class add --qdisc 1048576 --index 3 --rate 300kb/s
var tcCmd = &cobra.Command{
	Use: "tc",
}

var tcInitCmd = &cobra.Command{
	Use: "init",
	Run: initCmdFunc,
}

/***********************************************************
 * del
 ***********************************************************/

var tcDelCmd = &cobra.Command{
	Use: "del",
}

// var tcDelBpfCmd = &cobra.Command{
// 	Use: "bpf",
// 	Run: delBpfCmdFunc,
// }

var tcDelClassCmd = &cobra.Command{
	Use: "class",
	Run: delClassCmdFunc,
}

var tcDelIpCmd = &cobra.Command{
	Use: "ip",
	Run: delIpCmdFunc,
}

/***********************************************************
 * ls
 ***********************************************************/

var tcLsCmd = &cobra.Command{
	Use: "ls",
	Run: lsCmdFunc,
}

var tcLsBpfCmd = &cobra.Command{
	Use: "bpf",
	Run: lsBpfCmdFunc,
}

var tcLsClassCmd = &cobra.Command{
	Use: "class",
	Run: lsClassCmdFunc,
}

var tcLsIpCmd = &cobra.Command{
	Use: "ip",
	Run: lsIpCmdFunc,
}

/***********************************************************
 * add
 ***********************************************************/

var tcAddCmd = &cobra.Command{
	Use: "add",
}

// var tcAddBpfCmd = &cobra.Command{
// 	Use: "bpf",
// 	Run: addBpfCmdFunc,
// }

var tcAddClassCmd = &cobra.Command{
	Use: "class",
	Run: addClassCmdFunc,
}

var tcAddIpCmd = &cobra.Command{
	Use: "ip",
	Run: addIpCmdFunc,
}

func init() {
	tcCmd.PersistentFlags().StringVarP(&Interface, "interface", "i", "", "network interface such as eth0")
	tcCmd.MarkPersistentFlagRequired("interface")

	tcCmd.AddCommand(tcInitCmd)

	//********* add *************//
	tcCmd.AddCommand(tcAddCmd)

	//tcAddCmd.AddCommand(tcAddBpfCmd)
	//tcAddBpfCmd.Flags().Uint32P("qdisc", "q", 0, "Set qdisc handle")
	//tcAddBpfCmd.MarkFlagRequired("qdisc")

	tcAddCmd.AddCommand(tcAddClassCmd)
	tcAddClassCmd.Flags().Uint16P("index", "", 1, "class handle")
	tcAddClassCmd.Flags().StringP("rate", "r", "100KB/s", "Set traffic rate")
	tcAddClassCmd.Flags().Uint32P("qdisc", "q", 0, "Set qdisc handle")
	tcAddClassCmd.MarkFlagRequired("qdisc")

	tcAddCmd.AddCommand(tcAddIpCmd)
	tcAddIpCmd.Flags().Uint32P("class", "c", 1, "class handle")
	tcAddIpCmd.Flags().StringP("daddr", "d", "", "destination ip address")
	tcAddIpCmd.MarkFlagRequired("class")
	tcAddIpCmd.MarkFlagRequired("daddr")

	//********* ls *************//
	tcCmd.AddCommand(tcLsCmd)

	tcLsCmd.AddCommand(tcLsClassCmd)
	tcLsClassCmd.Flags().Uint32P("qdisc", "q", 0, "set qdisc handle")
	tcLsClassCmd.MarkFlagRequired("qdisc")

	tcLsCmd.AddCommand(tcLsIpCmd)

	tcLsCmd.AddCommand(tcLsBpfCmd)
	tcLsBpfCmd.Flags().Uint32P("qdisc", "q", 0, "set qdisc handle")
	tcLsBpfCmd.MarkFlagRequired("qdisc")

	//********* Del *************//
	tcCmd.AddCommand(tcDelCmd)

	//tcDelCmd.AddCommand(tcDelBpfCmd)
	//tcDelBpfCmd.Flags().Uint32P("qdisc", "q", 0, "set qdisc handle")

	tcDelCmd.AddCommand(tcDelClassCmd)
	tcDelClassCmd.Flags().Uint32P("qdisc", "q", 0, "set qdisc handle")
	tcDelClassCmd.Flags().Uint32P("class", "c", 1, "class handle")
	tcDelClassCmd.MarkFlagRequired("qdisc")
	tcDelClassCmd.MarkFlagRequired("class")

	tcDelCmd.AddCommand(tcDelIpCmd)
	tcDelIpCmd.Flags().StringP("daddr", "d", "", "destination ip address")
	tcDelIpCmd.MarkFlagRequired("daddr")
}

func initCmdFunc(command *cobra.Command, args []string) {
	err := user.InitTcQdisc(Interface)
	if err != nil {
		vlog.Println(err)
	} else {
		vlog.Println("init tc success")
	}
}

// func addBpfCmdFunc(command *cobra.Command, args []string) {
// 	qdisc := getFlagUint32(command, "qdisc")
// 	err := user.AttachEbpfTc(Interface, qdisc)
// 	if err != nil {
// 		vlog.Println(err)
// 	} else {
// 		vlog.Println("attach ebpf success")
// 	}

// }

func addClassCmdFunc(command *cobra.Command, args []string) {
	rate := getFlagString(command, "rate")
	qdisc := getFlagUint32(command, "qdisc")
	index := getFlagUint16(command, "index")
	err := user.AddTcClass(user.TcClassConfig{IfName: Interface, Qdisc: qdisc, Rate: rate, Index: index})
	if err != nil {
		vlog.Fatalln(err)
	} else {
		vlog.Println("add class success")
	}
}

func addIpCmdFunc(command *cobra.Command, args []string) {
	class := getFlagUint32(command, "class")
	daddr := getFlagString(command, "daddr")
	err := user.AddIp(daddr, class)

	if err != nil {
		vlog.Fatalln(err)
	} else {
		vlog.Println("add ip success")
	}
}

// func delBpfCmdFunc(command *cobra.Command, args []string) {
// 	qdisc := getFlagUint32(command, "qdisc")
// 	err := user.DeleteEbpfTc(Interface, qdisc)
// 	if err != nil {
// 		vlog.Fatalln(err)
// 	} else {
// 		vlog.Println("del ebpf success")
// 	}
// }

func delClassCmdFunc(command *cobra.Command, args []string) {
	qdisc := getFlagUint32(command, "qdisc")
	class := getFlagUint32(command, "class")
	err := user.DeleteTcClass(Interface, qdisc, class)
	if err != nil {
		vlog.Fatalln(err)
	} else {
		vlog.Println("del class success")
	}
}

func delIpCmdFunc(command *cobra.Command, args []string) {
	daddr := getFlagString(command, "daddr")
	err := user.DeleteIp(daddr)
	if err != nil {
		vlog.Fatalln(err)
	} else {
		vlog.Println("del ip success")
	}
}

func lsCmdFunc(command *cobra.Command, args []string) {
	err := user.LsTcQdisc(Interface)
	if err != nil {
		vlog.Fatalln(err)
	}
}

func lsBpfCmdFunc(command *cobra.Command, args []string) {
	qdisc := getFlagUint32(command, "qdisc")
	err := user.LsTcBpf(Interface, qdisc)
	if err != nil {
		vlog.Fatalln(err)
	}
}

func lsClassCmdFunc(command *cobra.Command, args []string) {
	qdisc := getFlagUint32(command, "qdisc")
	err := user.LsTcClass(Interface, qdisc)
	if err != nil {
		vlog.Fatalln(err)
	}
}

func lsIpCmdFunc(command *cobra.Command, args []string) {
	vlog.Println("ls ip")
	err := user.LsIp()
	if err != nil {
		vlog.Fatalln(err)
	}
}
