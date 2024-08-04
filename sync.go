package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"github.com/getlantern/systray"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// Config represents the configuration structure
type Config struct {
	SyncPairs []SyncPair `yaml:"sync_pairs"`
	Ignore    []string   `yaml:"ignore"`
}

// SyncPair represents a pair of directories to synchronize
type SyncPair struct {
	Source string `yaml:"source"`
	Target string `yaml:"target"`
}

// loadConfig loads the configuration from the specified file
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error loading config file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &config, nil
}

// shouldIgnore checks if a path should be ignored based on the ignore list
func shouldIgnore(path string, ignoreList []string) bool {
	for _, pattern := range ignoreList {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
	}
	return false
}

// syncFile synchronizes a single file
func syncFile(sourcePath, targetPath string) error {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Source file doesn't exist, try removing the target file
			err := os.Remove(targetPath)
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("error removing target file: %w", err)
			}
			logrus.WithFields(logrus.Fields{
				"source": sourcePath,
				"target": targetPath,
			}).Info("Source file does not exist, removed target file")
			return nil
		}

		// Handle access denied errors
		if errors.Is(err, syscall.EACCES) {
			logrus.WithFields(logrus.Fields{
				"source": sourcePath,
				"target": targetPath,
				"error":  err,
			}).Warn("Access denied to source file, skipping sync")
			return nil
		}

		return fmt.Errorf("error checking source file: %w", err)
	}
	defer sourceFile.Close()

	// Calculate source file hash
	sourceHash, err := getFileHash(sourcePath)
	if err != nil {
		// Handle incorrect function errors
		if errors.Is(err, syscall.EINVAL) {
			logrus.WithFields(logrus.Fields{
				"source": sourcePath,
				"target": targetPath,
				"error":  err,
			}).Warn("Incorrect function error while calculating source file hash, skipping sync")
			return nil
		}

		return fmt.Errorf("error calculating source file hash: %w", err)
	}

	// Check if target file exists and calculate its hash
	targetHash, err := getFileHash(targetPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error calculating target file hash: %w", err)
	}

	// Compare hashes
	if sourceHash == targetHash {
		logrus.WithFields(logrus.Fields{
			"source": sourcePath,
			"target": targetPath,
		}).Info("Files are identical, skipping sync")
		return nil
	}

	// Create or truncate target file
	targetFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("error creating target file: %w", err)
	}
	defer targetFile.Close()

	// Copy contents from source to target
	_, err = io.Copy(targetFile, sourceFile)
	if err != nil {
		return fmt.Errorf("error copying file: %w", err)
	}

	// Sync to ensure data is written to disk
	err = targetFile.Sync()
	if err != nil {
		return fmt.Errorf("error syncing target file: %w", err)
	}

	// Get source file info for timestamps
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		return fmt.Errorf("error getting source file info: %w", err)
	}

	// Set target file timestamps to match source
	err = os.Chtimes(targetPath, sourceInfo.ModTime(), sourceInfo.ModTime())
	if err != nil {
		return fmt.Errorf("error setting target file timestamps: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"source": sourcePath,
		"target": targetPath,
	}).Info("File synced successfully")

	return nil
}

// getFileHash calculates the SHA256 hash of a file
func getFileHash(filePath string) (string, error) {
	// Check if the path is a directory
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return "", err
	}
	if fileInfo.IsDir() {
		return "", fmt.Errorf("cannot calculate hash of directory: %s", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// syncDirectories synchronizes two directories bidirectionally
func syncDirectories(pair SyncPair, ignoreList []string) error {
	// Sync source to target
	err := filepath.Walk(pair.Source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Handle access denied errors
			if errors.Is(err, syscall.EACCES) {
				logrus.WithFields(logrus.Fields{
					"source": path,
					"error":  err,
				}).Warn("Access denied to source directory, skipping sync")
				return nil // Continue to the next file or directory
			}

			// Log other errors and continue
			logrus.WithFields(logrus.Fields{
				"source": path,
				"error":  err,
			}).Error("Error processing source file or directory")
			return nil // Continue to the next file or directory
		}

		relativePath, err := filepath.Rel(pair.Source, path)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"source": path,
				"error":  err,
			}).Error("Error getting relative path for source")
			return nil // Continue to the next file or directory
		}

		targetPath := filepath.Join(pair.Target, relativePath)

		if shouldIgnore(relativePath, ignoreList) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			err = os.MkdirAll(targetPath, info.Mode())
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"target": targetPath,
					"error":  err,
				}).Error("Error creating target directory")
				return nil // Continue to the next file or directory
			}
		} else {
			err = syncFile(path, targetPath)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"source": path,
					"target": targetPath,
					"error":  err,
				}).Error("Error syncing file")
				return nil // Continue to the next file or directory
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Sync target to source (similar error handling as above)
	err = filepath.Walk(pair.Target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, syscall.EACCES) {
				logrus.WithFields(logrus.Fields{
					"target": path,
					"error":  err,
				}).Warn("Access denied to target directory, skipping sync")
				return nil
			}

			logrus.WithFields(logrus.Fields{
				"target": path,
				"error":  err,
			}).Error("Error processing target file or directory")
			return nil
		}

		relativePath, err := filepath.Rel(pair.Target, path)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"target": path,
				"error":  err,
			}).Error("Error getting relative path for target")
			return nil
		}

		sourcePath := filepath.Join(pair.Source, relativePath)

		if shouldIgnore(relativePath, ignoreList) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			err = os.MkdirAll(sourcePath, info.Mode())
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"source": sourcePath,
					"error":  err,
				}).Error("Error creating source directory")
				return nil
			}
		} else {
			_, err := os.Stat(sourcePath)
			if os.IsNotExist(err) { // File exists in target but not in source
				err = syncFile(path, sourcePath)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"source": path,
						"target": sourcePath,
						"error":  err,
					}).Error("Error syncing file")
					return nil
				}
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// watchDirectory watches a directory for changes and synchronizes them bidirectionally
func watchDirectory(pair SyncPair, ignoreList []string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logrus.Fatalf("Error creating watcher: %v", err)
	}
	defer watcher.Close()

	err = watcher.Add(pair.Source)
	if err != nil {
		logrus.Fatalf("Error adding source directory to watcher: %v", err)
	}
	err = watcher.Add(pair.Target)
	if err != nil {
		logrus.Fatalf("Error adding target directory to watcher: %v", err)
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			logrus.WithFields(logrus.Fields{
				"event": event.Op,
				"path":  event.Name,
			}).Debug("Event received")

			// Ignore events for the directory itself
			if event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Remove == fsnotify.Remove {
				if stat, err := os.Stat(event.Name); err == nil && stat.IsDir() {
					continue
				}
			}

			// Determine the source and target paths based on the event
			var sourcePath, targetPath string
			if strings.HasPrefix(event.Name, pair.Source) {
				sourcePath = event.Name
				relativePath, err := filepath.Rel(pair.Source, event.Name)
				if err != nil {
					logrus.Errorf("Error getting relative path: %v", err)
					continue
				}
				targetPath = filepath.Join(pair.Target, relativePath)
			} else if strings.HasPrefix(event.Name, pair.Target) {
				targetPath = event.Name
				relativePath, err := filepath.Rel(pair.Target, event.Name)
				if err != nil {
					logrus.Errorf("Error getting relative path: %v", err)
					continue
				}
				sourcePath = filepath.Join(pair.Source, relativePath)
			} else {
				logrus.Warnf("Event from unknown directory: %s", event.Name)
				continue
			}

			if shouldIgnore(sourcePath, ignoreList) || shouldIgnore(targetPath, ignoreList) {
				continue
			}

			// Handle different event types
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				err := syncFile(sourcePath, targetPath)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"source": sourcePath,
						"target": targetPath,
					}).Errorf("Error syncing file: %v", err)
				}
			} else if event.Op&fsnotify.Remove == fsnotify.Remove {
				// Removing a file should be handled in both source and target
				var err error
				if strings.HasPrefix(event.Name, pair.Source) {
					relativePath, err := filepath.Rel(pair.Source, event.Name)
					if err != nil {
						logrus.Errorf("Error getting relative path: %v", err)
						continue
					}
					targetPath = filepath.Join(pair.Target, relativePath)
				} else if strings.HasPrefix(event.Name, pair.Target) {
					relativePath, err := filepath.Rel(pair.Target, event.Name)
					if err != nil {
						logrus.Errorf("Error getting relative path: %v", err)
						continue
					}
					sourcePath = filepath.Join(pair.Source, relativePath)
				}

				err = os.RemoveAll(targetPath)
				if err != nil && !os.IsNotExist(err) {
					logrus.WithFields(logrus.Fields{
						"path": targetPath,
					}).Errorf("Error removing file or directory: %v", err)
				}

				err = os.RemoveAll(sourcePath)
				if err != nil && !os.IsNotExist(err) {
					logrus.WithFields(logrus.Fields{
						"path": sourcePath,
					}).Errorf("Error removing file or directory: %v", err)
				}
			} else if event.Op&fsnotify.Rename == fsnotify.Rename {
				// Handle rename as remove and create
				var err error
				if strings.HasPrefix(event.Name, pair.Source) {
					relativePath, err := filepath.Rel(pair.Source, event.Name)
					if err != nil {
						logrus.Errorf("Error getting relative path: %v", err)
						continue
					}
					targetPath = filepath.Join(pair.Target, relativePath)
				} else if strings.HasPrefix(event.Name, pair.Target) {
					relativePath, err := filepath.Rel(pair.Target, event.Name)
					if err != nil {
						logrus.Errorf("Error getting relative path: %v", err)
						continue
					}
					sourcePath = filepath.Join(pair.Source, relativePath)
				}

				err = os.RemoveAll(targetPath)
				if err != nil && !os.IsNotExist(err) {
					logrus.WithFields(logrus.Fields{
						"path": targetPath,
					}).Errorf("Error removing file or directory: %v", err)
				}
				err = syncFile(sourcePath, targetPath)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"source": sourcePath,
						"target": targetPath,
					}).Errorf("Error syncing file: %v", err)
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logrus.Errorf("Watcher error: %v", err)
		}
	}
}

// onReady is called when the systray is ready
func onReady() {
	systray.SetIcon(getIcon("GoSync.ico")) // Replace with your icon file
	systray.SetTitle("GoSync")
	systray.SetTooltip("GoSync is running")

	mQuit := systray.AddMenuItem("Quit", "Quit GoSync")

	go func() {
		for range mQuit.ClickedCh {
			systray.Quit()
			return
		}
	}()

	// Start the synchronization and watching logic
	configFile := "config.yaml"
	config, err := loadConfig(configFile)
	if err != nil {
		logrus.Fatalf("Error loading config file: %v", err)
	}

	var wg sync.WaitGroup
	for _, pair := range config.SyncPairs {
		wg.Add(1)
		go func(pair SyncPair) {
			defer wg.Done()

			// Normalize paths to use the OS-specific separator
			pair.Source = filepath.Clean(pair.Source)
			pair.Target = filepath.Clean(pair.Target)

			logrus.WithFields(logrus.Fields{
				"source": pair.Source,
				"target": pair.Target,
			}).Info("Syncing directories")

			// Call syncDirectories for initial sync
			err := syncDirectories(pair, config.Ignore)
			if err != nil {
				logrus.Errorf("Error syncing directories: %v", err)
			}
			watchDirectory(pair, config.Ignore)
		}(pair)
	}

	wg.Wait()
}

// onExit is called when the systray is exiting
func onExit() {
	// Cleaning up here.
}

// getIcon loads the icon data from a file
func getIcon(s string) []byte {
	b, err := os.ReadFile(s)
	if err != nil {
		logrus.Errorf("Failed to read icon file: %v", err)
		return nil
	}
	return b
}

func main() {
	// Set logging level to error
	logrus.SetLevel(logrus.ErrorLevel)
	// Run the application in the system tray
	systray.Run(onReady, onExit)
}
