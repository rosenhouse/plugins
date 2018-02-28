package integration_test

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("Basic PTP using cnitool", func() {
	var (
		env         TestEnv
		nsShortName string
		nsLongName  string
	)

	BeforeEach(func() {
		cniPath, err := filepath.Abs("../bin")
		Expect(err).NotTo(HaveOccurred())
		netConfPath, err := filepath.Abs("./testdata")
		Expect(err).NotTo(HaveOccurred())

		env = TestEnv([]string{
			"CNI_PATH=" + cniPath,
			"NETCONFPATH=" + netConfPath,
			"PATH=" + os.Getenv("PATH"),
		})

		nsShortName = fmt.Sprintf("cni-test-%x", rand.Int31())
		nsLongName = fmt.Sprintf("/var/run/netns/" + nsShortName)
	})

	It("supports basic network add and del operations", func() {
		env.run("ip", "netns", "add", nsShortName)
		defer env.run("ip", "netns", "del", nsShortName)

		env.run(cnitoolBinPath, "add", "basic-ptp", nsLongName)

		addrOutput := env.run("ip", "-n", nsShortName, "addr")
		Expect(addrOutput).To(ContainSubstring("10.1.2."))

		env.run(cnitoolBinPath, "del", "basic-ptp", nsLongName)
	})

	It("supports add and del with chained plugins", func() {
		env.run("ip", "netns", "add", nsShortName)
		defer env.run("ip", "netns", "del", nsShortName)

		env.run(cnitoolBinPath, "add", "chained-ptp-bandwidth", nsLongName)

		addrOutput := env.run("ip", "-n", nsShortName, "addr")
		Expect(addrOutput).To(ContainSubstring("10.9.2."))

		env.run(cnitoolBinPath, "del", "chained-ptp-bandwidth", nsLongName)
	})
})

type TestEnv []string

func (e TestEnv) run(bin string, args ...string) string {
	cmd := exec.Command(bin, args...)
	cmd.Env = e
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session).Should(gexec.Exit(0))
	return string(session.Out.Contents())
}
