package testcases

import "strings"

// E2E-CLI-016 - Scanner has an invalid flag or invalid command
// an error message and return exit code 1
func init() { //nolint
	testSample := TestCase{
		Name: "should throw error messages for scanner flags [E2E-CLI-016]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan", "--invalid-flag"},
				[]string{"--invalid-flag"},
				[]string{"invalid"},
				[]string{"-i"},
			},
			ExpectedOutputFunc: []Validation{
				func(outputText string) bool {
					return strings.Contains(outputText, "flag provided but not defined: -invalid-flag")
				},
				func(outputText string) bool {
					return strings.Contains(outputText, "flag provided but not defined: -invalid-flag")
				},
				func(outputText string) bool {
					return strings.Contains(outputText, "No help topic for 'invalid'")
				},
				func(outputText string) bool {
					return strings.Contains(outputText, "flag provided but not defined: -i")
				},
			},
		},
		WantStatus: []int{126, 126, 3, 126},
	}
	Tests = append(Tests, testSample)
}
