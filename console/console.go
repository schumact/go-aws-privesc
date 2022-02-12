package console

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/desertbit/grumble"
	"github.com/fatih/color"
	"github.com/schumact/pacu-go/module"
)

var (
	// appConsole acts as a singleton for currentConsole
	appConsole   *currentConsole
	once         sync.Once
	originalName = "pacu-go" // original name for the grumble app's config
)

// currentConsole contains a pointer to a grumble app
type (
	currentConsole struct {
		app       *grumble.App
		profile   *aws.Config
		user      string
		dbManager *module.DbManager
	}
)

// setRegion sets currentConsole.profile.Region
func (cc *currentConsole) setRegion(r string) {
	cc.profile.Region = r
}

// getRegion returns currentConsole.profile.Region
func (cc *currentConsole) getRegion() (string, error) {
	if cc.profile == nil {
		return "", errors.New("aws config hasn't been set")
	}
	return cc.profile.Region, nil
}

// setProfile sets currentConsole.profile
func (cc *currentConsole) setProfile(conf *aws.Config) {
	cc.profile = conf
}

// getProfile returns currentConsole.Profile
func (cc *currentConsole) getProfile() (*aws.Config, error) {
	if cc.profile == nil {
		return nil, errors.New("aws config hasn't been set")
	}
	return cc.profile, nil
}

// getUser returns currentConsole.user
func (cc *currentConsole) getUser() (string, error) {
	if cc.user == "" {
		return "", errors.New("user hasn't been set")
	}
	return cc.user, nil
}

// setUser sets currentConsole.user
func (cc *currentConsole) setUser(user string) {
	cc.user = user
}

// setConsoleContext sets currentConsole.app.Config.Description
func (cc *currentConsole) setConsoleContext() {
	var (
		user   string
		region string
	)
	user, err := cc.getUser()
	if err != nil {
		cc.app.SetDefaultPrompt()
		return
	} else {
		region, err = cc.getRegion()
		if err != nil {
			cc.app.SetDefaultPrompt()
			return
		}
	}
	cc.app.SetPrompt(fmt.Sprintf("%s\\%s (%s) » ", originalName, user, region))
}

// setConsole sets appConsole, a currentConsole singleton
func setConsole(app *grumble.App) error {
	if appConsole == nil {
		manager, err := module.NewDbManager()
		if err != nil {
			return err
		}
		once.Do(func() {

			appConsole = &currentConsole{
				app:       app,
				dbManager: manager,
			}
		})
	}
	return nil
}

// getConsole gets appConsole, a currentConsole singleton
// if appConsole isn't set, an error is returned
func getConsole() (*currentConsole, error) {
	if appConsole == nil {
		return nil, errors.New("appConsole is nil")
	}
	return appConsole, nil
}

// printAsciiLogo prints ascii logo
func printAsciiLogo(a *grumble.App) {
	logo := `
	██████╗  █████╗  ██████╗██╗   ██╗       ██████╗  ██████╗ 
	██╔══██╗██╔══██╗██╔════╝██║   ██║      ██╔════╝ ██╔═══██╗
	██████╔╝███████║██║     ██║   ██║█████╗██║  ███╗██║   ██║
	██╔═══╝ ██╔══██║██║     ██║   ██║╚════╝██║   ██║██║   ██║
	██║     ██║  ██║╚██████╗╚██████╔╝      ╚██████╔╝╚██████╔╝
	╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝        ╚═════╝  ╚═════
	`

	fmt.Println(logo)
}

// splitArgs splits a string of args into a slice of strings (Args) for a module
func splitArgs(args string) []string {
	var argsList []string
	for _, v := range strings.Split(args, ",") {
		argsList = append(argsList, strings.TrimSpace(v))
	}
	// even if there is nothing in args, split will populate argsList with one element
	if len(argsList) == 1 && argsList[0] == "" {
		return make([]string, 0)
	}
	return argsList
}

// NewConsole creates a grumble console using OriginalConfig
func NewConsole() {
	app := grumble.New(&grumble.Config{
		Name: originalName,
		Description: "A tool for performing AWS privilege escalation. The escalation techniques were all taken from " +
			"https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/ and " +
			"https://bishopfox.com/blog/privilege-escalation-in-aws.",

		Flags: func(f *grumble.Flags) {
			f.String("d", "directory", "DEFAULT", "set an alternative directory path")
			f.Bool("v", "verbose", false, "enable verbose mode")
		},
		HelpHeadlineColor: color.New(color.FgBlue),
		ASCIILogoColor:    color.New(color.FgHiGreen),
	})

	addCommands(app)
	app.SetPrintASCIILogo(printAsciiLogo)
	if err := setConsole(app); err != nil {
		panic(err)
	}

	if err := app.Run(); err != nil {
		panic(err)
	}
}

// addCommands adds commands to a grumble app
func addCommands(app *grumble.App) {
	app.AddCommand(&grumble.Command{
		Name: "whoami",
		Help: "Outputs information for the current aws user",
		Run: func(c *grumble.Context) error {
			user, err := appConsole.getUser()
			if err != nil {
				fmt.Printf("[-] %v\n", err)
			} else {
				fmt.Printf("Current user: %s\n", user)
			}
			return nil
		},
	})

	app.AddCommand(&grumble.Command{
		Name: "list_modules",
		Help: "Lists all available privesc modules",
		Run: func(c *grumble.Context) error {
			module.ListModules()
			return nil
		},
	})

	app.AddCommand(&grumble.Command{
		Name: "module_help",
		Help: "Prints help information for a privesc module.",
		Args: func(a *grumble.Args) {
			a.String("module", "Name of module to print help for")
		},
		Run: func(c *grumble.Context) error {
			info, err := module.GetModuleHelp(c.Args.String("module"))
			if err != nil {
				fmt.Printf("[-] %v\n", err)
			} else {
				fmt.Println(info)
			}
			return nil
		},
	})

	app.AddCommand(&grumble.Command{
		Name: "run_module",
		Help: "Runs a privesc module",
		Args: func(a *grumble.Args) {
			a.String("module", "Name of the module to run. Use 'list_modules' to view available modules and their arguments")
		},
		Flags: func(f *grumble.Flags) {
			f.Bool("d", "dry_run", false, "Searches for privesc path but doesn't perform exploitation")
			f.String("a", "args", "", "Arguments for modules. Separate arguments by comma")
		},
		Run: func(c *grumble.Context) error {
			conf, err := appConsole.getProfile()
			if err != nil {
				fmt.Printf("[-] %v\n", err)
				return nil
			}
			user, err := appConsole.getUser()
			if err != nil {
				fmt.Printf("[-] %v\n", err)
				return nil
			}
			mod, err := module.ModuleFactory(c.Args.String("module"), conf, user)
			if err != nil {
				fmt.Printf("[-] %v\n", err)
				return nil
			}
			if ret, err := mod.Run(c.Flags.Bool("dry_run"), appConsole.dbManager, splitArgs(c.Flags.String("args"))...); err != nil {
				fmt.Printf("[-] %v\n", err)
			} else if ret == "" {
				fmt.Println("[*] no vulnerable policies found")
			} else {
				fmt.Printf("[+] %s\n", ret)
			}
			return nil
		},
	})

	app.AddCommand(&grumble.Command{
		Name: "set_config",
		Help: "Set AWS config for future command context. By default, the default aws profile is loaded.",
		Flags: func(f *grumble.Flags) {
			f.String("a", "access_key", "", "An aws user's access key")
			f.String("s", "secret_key", "", "An aws user's secret access key")
		},
		Run: func(c *grumble.Context) error {
			var (
				conf aws.Config
				err  error
			)
			if c.Flags.String("access_key") != "" && c.Flags.String("secret_key") != "" {
				conf, err = module.GetStaticConfig(c.Flags.String("access_key"), c.Flags.String("secret_key"))
			} else {
				conf, err = module.GetDefaultConfig()
			}
			if err != nil {
				fmt.Printf("[-] %v\n", err)
			} else {
				currConsole, err := getConsole()
				if err != nil {
					fmt.Printf("[-] %v\n", err)
					return nil
				}
				currConsole.setProfile(&conf)
			}
			return nil
		},
	})

	app.AddCommand(&grumble.Command{
		Name: "set_region",
		Help: "Set AWS region for future command context.",
		Args: func(a *grumble.Args) {
			a.String("region", "aws region to run modules in")
		},
		Run: func(c *grumble.Context) error {
			if cc, err := getConsole(); err != nil {
				fmt.Printf("[-] %v\n", err)
				return nil
			} else {
				cc.setRegion(c.Args.String("region"))
				cc.setConsoleContext()
			}
			return nil
		},
	})

	app.AddCommand(&grumble.Command{
		Name: "set_user",
		Help: "Sets a user for future commands. This user will be the target of IAM queries, etc.",
		Args: func(a *grumble.Args) {
			a.String("user", "iam user for aws")
		},
		Run: func(c *grumble.Context) error {
			if cc, err := getConsole(); err != nil {
				fmt.Printf("[-] %v\n", err)
				return nil
			} else {
				cc.setUser(c.Args.String("user"))
				cc.setConsoleContext()
			}
			return nil
		},
	})

	app.AddCommand(&grumble.Command{
		Name: "reset_user",
		Help: "Resets previously gathered user policies and lambda functions. By default, this program only queries IAM " +
			"once for all policies affecting a user and once for all lambda functions. This command whipes all data enumerated " +
			"for a user. Relevant info will be re-enumerated when running privesc modules",
		Args: func(a *grumble.Args) {
			a.String("user", "iam user for aws")
		},
		Run: func(c *grumble.Context) error {
			if err := appConsole.dbManager.ResetUser(c.Args.String("user")); err != nil {
				fmt.Printf("[-] %v\n", err)
			} else {
				fmt.Printf("[+] Reset policies for %s\n", c.Args.String("user"))
			}
			return nil
		},
	})
}
