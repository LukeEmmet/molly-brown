package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func generateDirectoryListing(URL *url.URL, path string, config Config) string {
	var listing string
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}
	listing = "# Directory listing\n\n"
	// Override with .mollyhead file
	header_path := filepath.Join(path, ".mollyhead")
	_, err = os.Stat(header_path)
	if err == nil {
		header, err := ioutil.ReadFile(header_path)
		if err == nil {
			listing = string(header)
		}
	}
	// Do "up" link first
	if URL.Path != "/" {
		if strings.HasSuffix(URL.Path, "/") {
			URL.Path = URL.Path[:len(URL.Path)-1]
		}
		up := filepath.Dir(URL.Path)
		listing += fmt.Sprintf("=> %s %s\n", up, "..")
	}
	// Sort files
	sort.SliceStable(files, func(i, j int) bool {
		if config.DirectoryReverse {
			i, j = j, i
		}
		if config.DirectorySort == "Name" {
			return files[i].Name() < files[j].Name()
		} else if config.DirectorySort == "Size" {
			return files[i].Size() < files[j].Size()
		} else if config.DirectorySort == "Time" {
			return files[i].ModTime().Before(files[j].ModTime())
		}
		return false // Should not happen
	})
	// Format lines
	for _, file := range files {
		// Skip dotfiles
		if strings.HasPrefix(file.Name(), ".") {
			continue
		}
		// Only list world readable files
		if uint64(file.Mode().Perm())&0444 != 0444 {
			continue
		}
		listing += fmt.Sprintf("=> %s %s\n", url.PathEscape(file.Name()), generatePrettyFileLabel(file, path, config))
	}
	return listing
}

func generatePrettyFileLabel(info os.FileInfo, path string, config Config) string {
	var size string
	if info.IsDir() {
		size = "        "
	} else if info.Size() < 1024 {
		size = fmt.Sprintf("%4d   B", info.Size())
	} else if info.Size() < (1024 << 10) {
		size = fmt.Sprintf("%4d KiB", info.Size()>>10)
	} else if info.Size() < 1024<<20 {
		size = fmt.Sprintf("%4d MiB", info.Size()>>20)
	} else if info.Size() < 1024<<30 {
		size = fmt.Sprintf("%4d GiB", info.Size()>>30)
	} else if info.Size() < 1024<<40 {
		size = fmt.Sprintf("%4d TiB", info.Size()>>40)
	} else {
		size = "GIGANTIC"
	}

	name := info.Name()
	if config.DirectoryTitles && filepath.Ext(name) == "."+config.GeminiExt {
		name = readHeading(path, info)
	}
	if len(name) > 40 {
		name = info.Name()[:36] + "..."
	}
	if info.IsDir() {
		name += "/"
	}
	return fmt.Sprintf("%-40s    %s   %v", name, size, info.ModTime().Format("Jan _2 2006"))
}

func readHeading(path string, info os.FileInfo) string {
	filePath := filepath.Join(path, info.Name())
	file, err := os.Open(filePath)
	if err != nil {
		return info.Name()
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(line[1:])
		}
	}
	return info.Name()
}
