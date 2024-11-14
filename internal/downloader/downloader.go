package downloader

import (
	"fmt"
	"regexp"
)

type Downloader interface {
	Download() error
}

func Download(source string, destination string) error {
	var downloader Downloader
	var err error
	if isOci(source) {
		downloader, err = NewOciDownloader(source, destination)
		if err != nil {
			return err
		}
	} else {
		downloader = NewArtifactDownloader(source, destination)
	}
	return downloader.Download()
}

func isOci(source string) bool {
	// Check whether this looks like an OCI endpoint
	// You can see the verification for the regex at https://regex101.com/r/Z8172m
	r := regexp.MustCompile(`(?i)^((http|https|oci)?:*/*)?([a-zA-Z.]*)+\.([a-zA-Z]*)/([\-_/a-zA-Z]*)(:.*)?$`)
	fmt.Println("is OCI", r.MatchString(source))
	return r.MatchString(source)
}
