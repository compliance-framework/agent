package downloader

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	parser "github.com/novln/docker-parser"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type OciDownloader struct {
	source      string
	destination string

	// Reference is the processed OCI Name of the Source
	reference *parser.Reference
}

func NewOciDownloader(source, destination string) (Downloader, error) {
	reference, err := getOciSpec(source)
	if err != nil {
		return nil, err
	}
	return &OciDownloader{
		source:      source,
		destination: destination,
		reference:   reference,
	}, nil
}

func (dl *OciDownloader) Download() error {
	outputDirectory, err := dl.outputDirectory()
	if err != nil {
		return err
	}

	pluginExecutableName := "plugin"

	pluginPath := filepath.Join(outputDirectory, fmt.Sprintf("%s/%s", dl.reference.ShortName(), dl.reference.Tag()))
	fmt.Println(pluginExecutableName)
	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		err = os.MkdirAll(pluginPath, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	}

	copyFolder := "/" // Folder to take from the image

	ctx := context.Background()

	token, err := dl.getAuthToken(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Got auth token:", token)

	manifest, err := dl.getImageManifest(ctx, token)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Got image manifest: %+v\n", manifest)

	layers, err := dl.downloadLayers(ctx, token, manifest)
	if err != nil {
		panic(err)
	}
	fmt.Println("Downloaded layers:", layers)

	err = dl.extractFolderFromLayers(layers, copyFolder, pluginPath)
	if err != nil {
		panic(err)
	}

	err = dl.cleanupLayers(layers)
	if err != nil {
		panic(err)
	}

	err = os.Chmod(pluginPath+"/"+pluginExecutableName, 0755)
	if err != nil {
		return fmt.Errorf("failed to make file executable: %w", err)
	}
	return err
}

func (dl *OciDownloader) outputDirectory() (string, error) {
	if path.IsAbs(dl.destination) {
		return path.Clean(dl.destination), nil
	} else {
		workDir, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return path.Join(workDir, dl.destination), nil
	}
}

func (dl *OciDownloader) getAuthToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/token?service=registry.docker.io&scope=repository:%s:pull", dl.reference.Registry(), dl.reference.Repository()), nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get auth token, status: %s, body: %s", resp.Status, string(body))
	}

	var result struct {
		Token string `json:"token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	return result.Token, nil
}

func (dl *OciDownloader) getImageManifest(ctx context.Context, token string) (*schema2Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/v2/%s/manifests/%s", dl.reference.Registry(), dl.reference.Repository(), dl.reference.Tag()), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get image manifest, status: %s, body: %s", resp.Status, string(body))
	}

	var index ociIndex
	err = json.NewDecoder(resp.Body).Decode(&index)
	if err != nil {
		return nil, err
	}

	// Handle OCI index to get the actual manifest
	for _, manifestDesc := range index.Manifests {
		if manifestDesc.MediaType == "application/vnd.docker.distribution.manifest.v2+json" ||
			manifestDesc.MediaType == "application/vnd.oci.image.manifest.v1+json" {
			return getManifestByDigest(ctx, token, manifestDesc.Digest, dl.reference.Registry(), dl.reference.Repository())
		}
	}

	return nil, fmt.Errorf("no valid manifest found in index")
}

func getManifestByDigest(ctx context.Context, token, digest string, registryURL string, repository string) (*schema2Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/v2/%s/manifests/%s", registryURL, repository, digest), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get image manifest by digest, status: %s, body: %s", resp.Status, string(body))
	}

	var manifest schema2Manifest
	err = json.NewDecoder(resp.Body).Decode(&manifest)
	if err != nil {
		return nil, err
	}

	return &manifest, nil
}

func (dl *OciDownloader) downloadLayers(ctx context.Context, token string, manifest *schema2Manifest) ([]string, error) {
	var layers []string

	for _, layer := range manifest.Layers {
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/v2/%s/blobs/%s", dl.reference.Registry(), dl.reference.Repository(), layer.Digest), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("failed to download layer %s, status: %s, body: %s", layer.Digest, resp.Status, string(body))
		}

		layerFile := fmt.Sprintf("%s.tar.gz", strings.TrimPrefix(layer.Digest, "sha256:"))
		outFile, err := os.Create(layerFile)
		if err != nil {
			return nil, err
		}

		fmt.Println("Downloading layer:", layer.Digest)
		_, err = io.Copy(outFile, resp.Body)
		if err != nil {
			outFile.Close()
			return nil, err
		}
		outFile.Close()

		layers = append(layers, layerFile)
	}

	return layers, nil
}

func (dl *OciDownloader) extractFolderFromLayers(layers []string, copyFolder string, destination string) error {
	for _, layerFile := range layers {
		layer, err := os.Open(layerFile)
		if err != nil {
			return err
		}
		defer layer.Close()

		gzipReader, err := gzip.NewReader(layer)
		if err != nil {
			return err
		}
		defer gzipReader.Close()

		tarReader := tar.NewReader(gzipReader)
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			if strings.HasPrefix(header.Name, strings.TrimPrefix(copyFolder, "/")) {
				// Remove the target folder prefix from the header name
				relativePath := strings.TrimPrefix(header.Name, strings.TrimPrefix(copyFolder, "/"))
				targetPath := filepath.Join(destination, relativePath)

				if header.Typeflag == tar.TypeDir {
					if err := os.MkdirAll(targetPath, 0755); err != nil {
						return err
					}
				} else {
					if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
						return err
					}
					outFile, err := os.Create(targetPath)
					if err != nil {
						return err
					}
					if _, err := io.Copy(outFile, tarReader); err != nil {
						outFile.Close()
						return err
					}
					outFile.Close()
				}
				fmt.Println("Extracted:", targetPath)
			}
		}
	}
	return nil
}

func (dl *OciDownloader) cleanupLayers(layers []string) error {
	for _, layerFile := range layers {
		err := os.Remove(layerFile)
		if err != nil {
			return fmt.Errorf("failed to remove layer file %s: %v", layerFile, err)
		}
		fmt.Println("Removed layer file:", layerFile)
	}
	return nil
}

func getOciSpec(source string) (*parser.Reference, error) {
	return parser.Parse(source)
}

type ociIndex struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Manifests     []struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	} `json:"manifests"`
}

type schema2Manifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	} `json:"layers"`
}
