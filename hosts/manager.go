package hosts

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

type Manager struct{}

func (m *Manager) Intercept(domains []string) error {
	if err := m.Clear(); err != nil {
		return err
	}
	return appendInterceptLines(domains)
}

func (m *Manager) Clear() error {
	return removeInterceptLines()
}

func removeInterceptLines() error {
	// Open the file for reading
	file, err := os.Open("/etc/hosts")
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Create a temporary slice to hold the file content
	var updatedLines []string
	inInterceptSection := false

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Check for the start marker
		if strings.TrimSpace(line) == "#### start intercept" {
			inInterceptSection = true
			continue // Skip the start marker line
		}

		// Check for the end marker
		if strings.TrimSpace(line) == "#### end intercept" {
			inInterceptSection = false
			continue // Skip the end marker line
		}

		// If not inside the intercept section, add the line to the updated lines slice
		if !inInterceptSection {
			updatedLines = append(updatedLines, line)
		}
	}

	// Handle any scanner errors
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading the file: %v", err)
	}

	// Create a temporary file
	tmpFile, err := ioutil.TempFile("/tmp", "hosts_*.tmp")
	if err != nil {
		return fmt.Errorf("error creating temp file: %v", err)
	}
	defer tmpFile.Close()

	// Remove any empty lines at the end of the file
	for len(updatedLines) > 0 && updatedLines[len(updatedLines)-1] == "" {
		updatedLines = updatedLines[:len(updatedLines)-1]
	}

	// Write the updated content back to the file
	writer := bufio.NewWriter(tmpFile)
	for _, line := range updatedLines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
	}

	// Ensure all buffered data is written to the file
	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush writer: %v", err)
	}

	err = os.Chmod(tmpFile.Name(), 0644)
	if err != nil {
		return fmt.Errorf("error changing file permissions: %v", err)
	}

	// Move the temp file to the target location with sudo
	err = exec.Command("sudo", "mv", tmpFile.Name(), "/etc/hosts").Run()
	if err != nil {
		return fmt.Errorf("error moving temp file to /etc/hosts: %v", err)
	}

	return nil
}

func appendInterceptLines(domains []string) error {
	toAppend := "\n\n\n#### start intercept\n"
	for _, domain := range domains {
		toAppend += fmt.Sprintf("127.0.0.1 %s\n", domain)
	}
	toAppend += "#### end intercept\n"

	// Open the /etc/hosts file for reading
	file, err := os.Open("/etc/hosts")
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Create a temporary file to write the new contents
	tmpFile, err := ioutil.TempFile("/tmp", "hosts_*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// Copy the contents of the original file to the temporary file
	scanner := bufio.NewScanner(file)
	writer := bufio.NewWriter(tmpFile)

	for scanner.Scan() {
		_, err := writer.WriteString(scanner.Text() + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to temp file: %v", err)
		}
	}

	// Check for any scanner errors
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading the file: %v", err)
	}

	// Append the new line to the temporary file
	_, err = writer.WriteString(toAppend)
	if err != nil {
		return fmt.Errorf("failed to append to temp file: %v", err)
	}

	// Ensure all data is written to the temp file
	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush writer: %v", err)
	}

	err = os.Chmod(tmpFile.Name(), 0644)
	if err != nil {
		return fmt.Errorf("error changing file permissions: %v", err)
	}

	// Use sudo to move the temporary file to /etc/hosts
	err = exec.Command("sudo", "mv", tmpFile.Name(), "/etc/hosts").Run()
	if err != nil {
		return fmt.Errorf("failed to move temp file to /etc/hosts: %v", err)
	}

	return nil
}
