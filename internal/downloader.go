package internal

// We want to download either plugin binaries, or opa bundles

// A plugin is multi architecture, and we need to download the correct one for the current runtime
// A bundle is simply a tar file of OPA policies
//
//func DownloadPackages(packages []model.Package) error {
//	// We should not be doing a waitgroup here. This is a higher level decision.
//	// This function is responsible for downloading one artifact.
//	var wg sync.WaitGroup
//	var errorCh = make(chan error)
//
//	ex, err := os.Executable()
//	if err != nil {
//		panic(err)
//	}
//	pluginsPath := filepath.Join(filepath.Dir(ex), "./plugins")
//	if _, err := os.Stat(pluginsPath); os.IsNotExist(err) {
//		err = os.MkdirAll(pluginsPath, 0755)
//		if err != nil {
//			log.Errorf("Failed to create directory: %v", err)
//			return err
//		}
//	}
//
//	for _, pkg := range packages {
//		wg.Add(1)
//		go func(p model.Package) {
//			defer wg.Done()
//			log.WithFields(log.Fields{
//				"package": p.Name,
//				"Tag":     p.Tag,
//				"image":   p.Image,
//			}).Info("Downloading package")
//			if err := downloadPackage(p); err != nil {
//				errorCh <- err
//			} else {
//				log.WithFields(log.Fields{
//					"package": p.Name,
//					"tag":     p.Tag,
//					"image":   p.Image,
//				}).Info("Downloaded package")
//			}
//		}(pkg)
//	}
//
//	go func() {
//		wg.Wait()
//		close(errorCh)
//	}()
//
//	var errs []error
//	for err := range errorCh {
//		if err != nil {
//			errs = append(errs, err)
//		}
//	}
//
//	if len(errs) > 0 {
//		return fmt.Errorf("encountered %d errors during download: %v", len(errs), errs)
//	}
//
//	return nil
//}
//
//func downloadPackage(p model.Package) error {
//	ex, err := os.Executable()
//	if err != nil {
//		panic(err)
//	}
//
//	currentPath := filepath.Dir(ex)
//	pluginsPath := currentPath + "/plugins"
//	pluginName := p.Name
//	pluginExecutableName := "plugin"
//	pluginTag := p.Tag
//	imageSpec := p.Image
//
//	pluginPath := filepath.Join(pluginsPath, fmt.Sprintf("%s/%s", pluginName, pluginTag))
//	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
//		err = os.MkdirAll(pluginPath, 0755)
//		if err != nil {
//			return fmt.Errorf("failed to create directory: %v", err)
//		}
//	}
//
//	if !strings.HasPrefix(imageSpec, "http") {
//		imageSpec = "https://" + imageSpec
//	} else {
//		imageSpec = imageSpec
//	}
//	registryURL, repository, err := splitDockerImageSpec(imageSpec)
//	if err != nil {
//		fmt.Printf("Error in splitDockerImageSpec: %v\n", err)
//	}
//
//	repository = stripAfterColon(repository)
//	authURL := registryURL + "/token"
//	copyFolder := "/compliance-framework" // Folder to take from the image
//
//	err = getDockerImageFolder(registryURL, repository, pluginTag, authURL, copyFolder, pluginPath)
//	if err != nil {
//		fmt.Printf("Error extracting folder: %v\n", err)
//	}
//
//	err = os.Chmod(pluginPath+"/"+pluginExecutableName, 0755)
//	if err != nil {
//		return fmt.Errorf("failed to make file executable: %w", err)
//	}
//	return err
//}
//
//func stripAfterColon(input string) string {
//	if idx := strings.Index(input, ":"); idx != -1 {
//		return input[:idx]
//	}
//	return input
//}
//
//func splitDockerImageSpec(imageSpec string) (registryUrl string, repository string, err error) {
//	parsedUrl, err := url.Parse(imageSpec)
//	if err != nil {
//		return "", "", err
//	}
//
//	// Ensure the URL has a scheme
//	if parsedUrl.Scheme == "" {
//		return "", "", fmt.Errorf("invalid image spec: missing scheme")
//	}
//
//	// Extract the registry URL and repository path
//	registryUrl = fmt.Sprintf("%s://%s", parsedUrl.Scheme, parsedUrl.Host)
//	repository = strings.TrimPrefix(parsedUrl.Path, "/")
//
//	return registryUrl, repository, nil
//}
//
//func getDockerImageFolder(registryURL string, repository string, tag string, authURL string, copyFolder string, destination string) error {
//	ctx := context.Background()
//
//	token, err := getAuthToken(ctx, repository, authURL)
//	if err != nil {
//		panic(err)
//	}
//	fmt.Println("Got auth token:", token)
//
//	manifest, err := getImageManifest(ctx, token, registryURL, repository, tag)
//	if err != nil {
//		panic(err)
//	}
//	fmt.Printf("Got image manifest: %+v\n", manifest)
//
//	layers, err := downloadLayers(ctx, token, manifest, registryURL, repository)
//	if err != nil {
//		panic(err)
//	}
//	fmt.Println("Downloaded layers:", layers)
//
//	err = extractFolderFromLayers(layers, copyFolder, destination)
//	if err != nil {
//		panic(err)
//	}
//
//	err = cleanupLayers(layers)
//	if err != nil {
//		panic(err)
//	}
//
//	fmt.Println("Folder successfully extracted and cleanup complete")
//	return nil
//}
//
//func getAuthToken(ctx context.Context, repository string, authURL string) (string, error) {
//	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s?service=registry.docker.io&scope=repository:%s:pull", authURL, repository), nil)
//	if err != nil {
//		return "", err
//	}
//
//	resp, err := http.DefaultClient.Do(req)
//	if err != nil {
//		return "", err
//	}
//	defer resp.Body.Close()
//
//	if resp.StatusCode != http.StatusOK {
//		body, _ := io.ReadAll(resp.Body)
//		return "", fmt.Errorf("failed to get auth token, status: %s, body: %s", resp.Status, string(body))
//	}
//
//	var result struct {
//		Token string `json:"token"`
//	}
//	err = json.NewDecoder(resp.Body).Decode(&result)
//	if err != nil {
//		return "", err
//	}
//
//	return result.Token, nil
//}
//
//func getImageManifest(ctx context.Context, token string, registryURL string, repository string, tag string) (*schema2Manifest, error) {
//	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/v2/%s/manifests/%s", registryURL, repository, tag), nil)
//	if err != nil {
//		return nil, err
//	}
//	req.Header.Set("Authorization", "Bearer "+token)
//	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json")
//
//	resp, err := http.DefaultClient.Do(req)
//	if err != nil {
//		return nil, err
//	}
//	defer resp.Body.Close()
//
//	if resp.StatusCode != http.StatusOK {
//		body, _ := io.ReadAll(resp.Body)
//		return nil, fmt.Errorf("failed to get image manifest, status: %s, body: %s", resp.Status, string(body))
//	}
//
//	var index ociIndex
//	err = json.NewDecoder(resp.Body).Decode(&index)
//	if err != nil {
//		return nil, err
//	}
//
//	// Handle OCI index to get the actual manifest
//	for _, manifestDesc := range index.Manifests {
//		if manifestDesc.MediaType == "application/vnd.docker.distribution.manifest.v2+json" ||
//			manifestDesc.MediaType == "application/vnd.oci.image.manifest.v1+json" {
//			return getManifestByDigest(ctx, token, manifestDesc.Digest, registryURL, repository)
//		}
//	}
//
//	return nil, fmt.Errorf("no valid manifest found in index")
//}
//
//func getManifestByDigest(ctx context.Context, token, digest string, registryURL string, repository string) (*schema2Manifest, error) {
//	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/v2/%s/manifests/%s", registryURL, repository, digest), nil)
//	if err != nil {
//		return nil, err
//	}
//	req.Header.Set("Authorization", "Bearer "+token)
//	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json")
//
//	resp, err := http.DefaultClient.Do(req)
//	if err != nil {
//		return nil, err
//	}
//	defer resp.Body.Close()
//
//	if resp.StatusCode != http.StatusOK {
//		body, _ := io.ReadAll(resp.Body)
//		return nil, fmt.Errorf("failed to get image manifest by digest, status: %s, body: %s", resp.Status, string(body))
//	}
//
//	var manifest schema2Manifest
//	err = json.NewDecoder(resp.Body).Decode(&manifest)
//	if err != nil {
//		return nil, err
//	}
//
//	return &manifest, nil
//}
//
//func downloadLayers(ctx context.Context, token string, manifest *schema2Manifest, registryURL string, repository string) ([]string, error) {
//	var layers []string
//
//	for _, layer := range manifest.Layers {
//		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/v2/%s/blobs/%s", registryURL, repository, layer.Digest), nil)
//		if err != nil {
//			return nil, err
//		}
//		req.Header.Set("Authorization", "Bearer "+token)
//
//		resp, err := http.DefaultClient.Do(req)
//		if err != nil {
//			return nil, err
//		}
//		defer resp.Body.Close()
//
//		if resp.StatusCode != http.StatusOK {
//			body, _ := io.ReadAll(resp.Body)
//			return nil, fmt.Errorf("failed to download layer %s, status: %s, body: %s", layer.Digest, resp.Status, string(body))
//		}
//
//		layerFile := fmt.Sprintf("%s.tar.gz", strings.TrimPrefix(layer.Digest, "sha256:"))
//		outFile, err := os.Create(layerFile)
//		if err != nil {
//			return nil, err
//		}
//
//		fmt.Println("Downloading layer:", layer.Digest)
//		_, err = io.Copy(outFile, resp.Body)
//		if err != nil {
//			outFile.Close()
//			return nil, err
//		}
//		outFile.Close()
//
//		layers = append(layers, layerFile)
//	}
//
//	return layers, nil
//}
//
//func extractFolderFromLayers(layers []string, copyFolder string, destination string) error {
//	for _, layerFile := range layers {
//		layer, err := os.Open(layerFile)
//		if err != nil {
//			return err
//		}
//		defer layer.Close()
//
//		gzipReader, err := gzip.NewReader(layer)
//		if err != nil {
//			return err
//		}
//		defer gzipReader.Close()
//
//		tarReader := tar.NewReader(gzipReader)
//		for {
//			header, err := tarReader.Next()
//			if err == io.EOF {
//				break
//			}
//			if err != nil {
//				return err
//			}
//
//			if strings.HasPrefix(header.Name, strings.TrimPrefix(copyFolder, "/")) {
//				// Remove the target folder prefix from the header name
//				relativePath := strings.TrimPrefix(header.Name, strings.TrimPrefix(copyFolder, "/"))
//				targetPath := filepath.Join(destination, relativePath)
//
//				if header.Typeflag == tar.TypeDir {
//					if err := os.MkdirAll(targetPath, 0755); err != nil {
//						return err
//					}
//				} else {
//					if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
//						return err
//					}
//					outFile, err := os.Create(targetPath)
//					if err != nil {
//						return err
//					}
//					if _, err := io.Copy(outFile, tarReader); err != nil {
//						outFile.Close()
//						return err
//					}
//					outFile.Close()
//				}
//				fmt.Println("Extracted:", targetPath)
//			}
//		}
//	}
//	return nil
//}
//
//func cleanupLayers(layers []string) error {
//	for _, layerFile := range layers {
//		err := os.Remove(layerFile)
//		if err != nil {
//			return fmt.Errorf("failed to remove layer file %s: %v", layerFile, err)
//		}
//		fmt.Println("Removed layer file:", layerFile)
//	}
//	return nil
//}
//
//type ociIndex struct {
//	SchemaVersion int    `json:"schemaVersion"`
//	MediaType     string `json:"mediaType"`
//	Manifests     []struct {
//		MediaType string `json:"mediaType"`
//		Size      int    `json:"size"`
//		Digest    string `json:"digest"`
//	} `json:"manifests"`
//}
//
//type schema2Manifest struct {
//	SchemaVersion int    `json:"schemaVersion"`
//	MediaType     string `json:"mediaType"`
//	Config        struct {
//		MediaType string `json:"mediaType"`
//		Size      int    `json:"size"`
//		Digest    string `json:"digest"`
//	} `json:"config"`
//	Layers []struct {
//		MediaType string `json:"mediaType"`
//		Size      int    `json:"size"`
//		Digest    string `json:"digest"`
//	} `json:"layers"`
//}
