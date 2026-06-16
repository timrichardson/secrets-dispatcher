package securelocal

import (
	"fmt"
	"os"

	"github.com/nikicat/secrets-dispatcher/internal/securebackend"
)

type CheckResult struct {
	Name    string
	Pass    bool
	Message string
}

func Check(cfg ProvisionConfig) []CheckResult {
	cfg.defaults()
	var results []CheckResult

	_, providerErr := cfg.provider()
	results = append(results, CheckResult{
		Name: "secure backend provider supported",
		Pass: providerErr == nil,
		Message: passOrFix(providerErr == nil,
			fmt.Sprintf("provider %q is supported", cfg.Provider),
			providerErrString(providerErr),
		),
	})

	_, desktopErr := userLookupFunc(cfg.DesktopUser)
	results = append(results, CheckResult{
		Name: "desktop user exists",
		Pass: desktopErr == nil,
		Message: passOrFix(desktopErr == nil,
			fmt.Sprintf("desktop user %q found", cfg.DesktopUser),
			"specify an existing desktop user with --user",
		),
	})

	backend, backendErr := userLookupFunc(cfg.BackendUser)
	results = append(results, CheckResult{
		Name: "backend user exists",
		Pass: backendErr == nil,
		Message: passOrFix(backendErr == nil,
			fmt.Sprintf("backend user %q found", cfg.BackendUser),
			fmt.Sprintf("run: sudo secrets-dispatcher provision --mode secure-local --user %s", cfg.DesktopUser),
		),
	})

	homeInfo, homeErr := os.Stat(cfg.backendHome())
	homeExists := homeErr == nil && homeInfo.IsDir()
	results = append(results, CheckResult{
		Name: "backend home exists",
		Pass: homeExists,
		Message: passOrFix(homeExists,
			fmt.Sprintf("backend home %q exists", cfg.backendHome()),
			fmt.Sprintf("run: sudo secrets-dispatcher provision --mode secure-local --user %s", cfg.DesktopUser),
		),
	})
	modeOK := homeExists && homeInfo.Mode().Perm() == 0700
	results = append(results, CheckResult{
		Name: "backend home mode 0700",
		Pass: modeOK,
		Message: passOrFix(modeOK,
			"backend home has mode 0700",
			fmt.Sprintf("run: sudo chmod 0700 %s", cfg.backendHome()),
		),
	})

	unitExists := fileExists(SystemUnitPath)
	results = append(results, CheckResult{
		Name: "secure systemd unit exists",
		Pass: unitExists,
		Message: passOrFix(unitExists,
			fmt.Sprintf("unit %q exists", SystemUnitPath),
			fmt.Sprintf("run: sudo secrets-dispatcher provision --mode secure-local --user %s", cfg.DesktopUser),
		),
	})

	binaryErr := validateRootUnitBinaryPath(cfg.BinaryPath)
	results = append(results, CheckResult{
		Name: "secure unit binary path safe",
		Pass: binaryErr == nil,
		Message: passOrFix(binaryErr == nil,
			fmt.Sprintf("binary path %q is safe for a root-owned unit", cfg.BinaryPath),
			binaryErrString(binaryErr),
		),
	})

	if backendErr == nil {
		results = append(results, CheckResult{
			Name: "backend user uid resolved",
			Pass: backend.Uid != "",
			Message: passOrFix(backend.Uid != "",
				fmt.Sprintf("backend UID is %s", backend.Uid),
				"backend user lookup returned an empty UID",
			),
		})
	}

	return results
}

func (c ProvisionConfig) provider() (string, error) {
	provider, err := securebackendProvider(c.Provider)
	if err != nil {
		return "", err
	}
	return provider, nil
}

func securebackendProvider(provider string) (string, error) {
	if _, err := securebackend.NewProvider(provider); err != nil {
		return "", err
	}
	return provider, nil
}

func passOrFix(ok bool, passMsg, fixMsg string) string {
	if ok {
		return passMsg
	}
	return fixMsg
}

func providerErrString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func binaryErrString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
