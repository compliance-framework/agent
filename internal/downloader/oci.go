package downloader

import (
	"github.com/chris-cmsoft/concom/internal"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"os"
	"path"
)

type OciDownloader struct {
	source      string
	destination string

	// Reference is the processed OCI Name of the Source
	reference name.Reference
}

func NewOciDownloader(source, destination string) (Downloader, error) {
	reference, err := name.ParseReference(source)
	if err != nil {
		return nil, err
	}
	return &OciDownloader{
		source:      source,
		destination: destination,
		reference:   reference,
	}, nil
}

func (dl *OciDownloader) GetOutputDirectory() (string, error) {
	var outputDirectory string
	if path.IsAbs(dl.destination) {
		outputDirectory = path.Join(dl.destination, dl.reference.Context().RepositoryStr(), dl.reference.Identifier())
	} else {
		workDir, err := os.Getwd()
		if err != nil {
			return "", err
		}
		outputDirectory = path.Join(workDir, dl.destination, dl.reference.Context().RepositoryStr(), dl.reference.Identifier())
	}
	return outputDirectory, nil
}

func (dl *OciDownloader) Download() error {

	ref, err := name.ParseReference(dl.source)
	if err != nil {
		return err
	}

	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return err
	}

	outputDirectory, err := dl.GetOutputDirectory()
	if err != nil {
		return err
	}

	err = os.MkdirAll(outputDirectory, 0755)
	if err != nil {
		return err
	}

	layers, err := img.Layers()
	for _, layer := range layers {
		layerReader, err := layer.Uncompressed()
		if err != nil {
			return err
		}
		err = internal.Untar(outputDirectory, layerReader)
		if err != nil {
			return err
		}
	}

	return nil
}
