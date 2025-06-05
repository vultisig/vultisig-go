package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// AskForConfirmation prompts the user for a yes/no confirmation
func AskForConfirmation(question string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", question)

	response, err := reader.ReadString('\n')
	if err != nil {
		logrus.WithError(err).Error("Failed to read user input")
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}