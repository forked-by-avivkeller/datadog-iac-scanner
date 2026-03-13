package testcases

import "strings"

// E2E-CLI-003 - Scan command has a mandatory flag -p. The CLI should exhibit
// an error message and return exit code 126
func init() { //nolint
	testSample := TestCase{
		Name: "should display an error regarding missing -p flag [E2E-CLI-003]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan"},
			},
			ExpectedOutputFunc: []Validation{
				func(outputText string) bool {
					return strings.Contains(outputText, "Program failed: Required flag \"path\" not set")
				},
			},
		},
		WantStatus: []int{126},
	}

	Tests = append(Tests, testSample)
}
