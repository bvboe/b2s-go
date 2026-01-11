package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	// Import SQLite driver for syft RPM database parsing
	// Syft requires this for scanning images with RPM packages (RHEL, CentOS, Fedora, etc.)
	_ "modernc.org/sqlite"
)

const (
	// Default namespace for Kubernetes
	k8sNamespace = "k8s.io"
)

var (
	// Known containerd socket locations for different Kubernetes distributions
	containerdSocketPaths = []string{
		"/run/containerd/containerd.sock",               // Standard Kubernetes
		"/run/k3s/containerd/containerd.sock",           // K3s
		"/var/snap/microk8s/common/run/containerd.sock", // MicroK8s
		"/run/dockershim.sock",                          // Legacy dockershim
	}
)

// computeChainID computes the chain ID from a list of diff IDs
// This follows the containerd/OCI spec for computing chain IDs
func computeChainID(diffIDs []digest.Digest) digest.Digest {
	if len(diffIDs) == 0 {
		return ""
	}
	if len(diffIDs) == 1 {
		return diffIDs[0]
	}

	// Chain the diff IDs together: chainID = SHA256(parent + " " + diffID)
	parent := diffIDs[0]
	for i := 1; i < len(diffIDs); i++ {
		h := sha256.New()
		h.Write([]byte(parent.String()))
		h.Write([]byte(" "))
		h.Write([]byte(diffIDs[i].String()))
		parent = digest.NewDigest(digest.SHA256, h)
	}
	return parent
}

// containsPlatformSuffix checks if image name contains platform-specific suffix
func containsPlatformSuffix(name string) bool {
	// Check for common platform suffixes in image names
	platforms := []string{"-arm64", "-amd64", "-arm", "-386", "-ppc64le", "-s390x"}
	for _, platform := range platforms {
		if len(name) > len(platform) {
			// Check if platform appears before version tag (e.g., "image-arm64:v1.0")
			for i := len(name) - len(platform) - 1; i >= 0; i-- {
				if name[i] == ':' || name[i] == '@' {
					break // reached tag/digest, stop searching
				}
				if i+len(platform) < len(name) && name[i:i+len(platform)] == platform {
					nextChar := name[i+len(platform)]
					if nextChar == ':' || nextChar == '@' || nextChar == '/' {
						return true
					}
				}
			}
		}
	}
	return false
}

// ContainerDClient implements RuntimeClient for ContainerD daemon
type ContainerDClient struct {
	client     *containerd.Client
	socketPath string
}

// tryContainerdSocket attempts to create a working containerd client for the given socket
// Returns the client if successful, nil if the socket doesn't work
func tryContainerdSocket(socketPath string) (*containerd.Client, error) {
	// Check if socket file exists first
	if _, err := os.Stat(socketPath); err != nil {
		return nil, fmt.Errorf("socket file not found: %w", err)
	}

	// Try to create containerd client
	client, err := containerd.New(socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// Verify the connection actually works by calling Version()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Version(ctx)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connection test failed: %w", err)
	}

	return client, nil
}

// NewContainerDClient creates a new ContainerD runtime client
// Auto-detects socket location for K3s, MicroK8s, and standard Kubernetes
// Tries each socket and verifies the connection works
func NewContainerDClient() *ContainerDClient {
	var socketPaths []string

	// Check environment variable override first
	if envSocket := os.Getenv("CONTAINERD_SOCKET"); envSocket != "" {
		log.Printf("CONTAINERD_SOCKET set to: %s", envSocket)
		socketPaths = append(socketPaths, envSocket)
	}

	// Add known socket locations
	socketPaths = append(socketPaths, containerdSocketPaths...)

	// Try each socket until we find one that works
	for _, socketPath := range socketPaths {
		log.Printf("Trying containerd socket: %s", socketPath)
		client, err := tryContainerdSocket(socketPath)
		if err != nil {
			log.Printf("  Socket %s not usable: %v", socketPath, err)
			continue
		}

		log.Printf("Successfully connected to containerd via: %s", socketPath)
		return &ContainerDClient{client: client, socketPath: socketPath}
	}

	// No working socket found
	log.Printf("Failed to find any working containerd socket (tried: %v)", socketPaths)
	return &ContainerDClient{client: nil, socketPath: ""}
}

// IsAvailable checks if ContainerD daemon is accessible
func (c *ContainerDClient) IsAvailable() bool {
	if c.client == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Try to get version to check connectivity
	_, err := c.client.Version(ctx)
	return err == nil
}

// Name returns the runtime name
func (c *ContainerDClient) Name() string {
	return "containerd"
}

// GenerateSBOM generates an SBOM for the given image digest
// Uses OCI export to handle discard_unpacked_layers=true
func (c *ContainerDClient) GenerateSBOM(ctx context.Context, digest string) ([]byte, error) {
	if c.client == nil {
		return nil, fmt.Errorf("ContainerD client not initialized")
	}

	// Use k8s.io namespace (Kubernetes uses this)
	ctx = namespaces.WithNamespace(ctx, k8sNamespace)

	// Find image by digest
	imageService := c.client.ImageService()
	images, err := imageService.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list ContainerD images: %w", err)
	}

	var imageRef string
	var targetDigest string
	log.Printf("Looking for digest: %s", digest)
	log.Printf("Found %d images in ContainerD", len(images))

	// First pass: find the image by digest and get its Target.Digest
	for _, img := range images {
		imgDigest := img.Target.Digest.String()
		log.Printf("  Image: %s, Digest: %s", img.Name, imgDigest)

		// Check if digest matches in Target.Digest (manifest digest)
		if imgDigest == digest || "sha256:"+imgDigest == digest || imgDigest == "sha256:"+digest {
			imageRef = img.Name
			targetDigest = imgDigest
			log.Printf("Found matching image by manifest digest: %s", imageRef)
			break
		}

		// Also check if img.Name contains the digest (config digest from Kubernetes)
		if img.Name == digest || "sha256:"+img.Name == digest || img.Name == "sha256:"+digest {
			imageRef = img.Name
			targetDigest = imgDigest
			log.Printf("Found matching image by name digest: %s", imageRef)
			break
		}
	}

	if imageRef == "" {
		log.Printf("Image digest %s not found. Searched %d images.", digest, len(images))
		return nil, fmt.Errorf("image with digest %s not found in ContainerD", digest)
	}

	// If we found a bare digest reference (like "sha256:abc123..."), try to find a named reference
	// with the same Target.Digest. Prefer platform-specific names (e.g., with "-arm64") that actually
	// have content available, as containerd discards layers for other platforms
	if len(imageRef) > 7 && imageRef[:7] == "sha256:" {
		log.Printf("Found digest-only reference, looking for named reference with same target digest...")
		var fallbackRef string
		for _, img := range images {
			// Look for ANY named image (not starting with sha256:) with the same target digest
			if img.Target.Digest.String() == targetDigest && len(img.Name) > 7 && img.Name[:7] != "sha256:" {
				// Prefer platform-specific image names (containing "-arm64", "-amd64", etc.)
				// These actually have content available in containerd
				if len(fallbackRef) == 0 {
					fallbackRef = img.Name // Use as fallback
				}
				// Check if this is a platform-specific image name
				if len(img.Name) > 6 && ((len(img.Name) >= 10 && img.Name[len(img.Name)-10:] == "-arm64:") ||
					(len(img.Name) >= 10 && img.Name[len(img.Name)-10:] == "-amd64:") ||
					containsPlatformSuffix(img.Name)) {
					log.Printf("Found platform-specific named reference: %s", img.Name)
					imageRef = img.Name
					break
				}
			}
		}
		// If no platform-specific image found, use fallback
		if imageRef[:7] == "sha256:" && len(fallbackRef) > 0 {
			log.Printf("Using fallback named reference: %s", fallbackRef)
			imageRef = fallbackRef
		}
	}

	log.Printf("Generating SBOM for ContainerD image: %s (digest=%s)", imageRef, digest)

	// Use snapshot-based scanning to avoid export issues with discard_unpacked_layers=true
	// This scans the actual unpacked filesystem from containerd's snapshots
	img, err := c.client.GetImage(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get image %s: %w", imageRef, err)
	}

	// Unpack the image to ensure snapshots exist
	log.Printf("Unpacking image (if needed): %s", imageRef)
	snapshotterName := "overlayfs" // Default snapshotter for containerd
	unpacked, err := img.IsUnpacked(ctx, snapshotterName)
	if err != nil {
		return nil, fmt.Errorf("failed to check if image is unpacked: %w", err)
	}
	if !unpacked {
		if err := img.Unpack(ctx, snapshotterName); err != nil {
			return nil, fmt.Errorf("failed to unpack image: %w", err)
		}
		log.Printf("Image unpacked successfully")
	}

	// Get the snapshot mounts for the image
	diffIDs, err := img.RootFS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get rootfs: %w", err)
	}

	// Compute chain ID from diff IDs
	chainID := computeChainID(diffIDs).String()
	log.Printf("Getting snapshot mounts for chain ID: %s", chainID)

	snapshotter := c.client.SnapshotService(snapshotterName)

	// Create a view snapshot to allow mounting
	// View snapshots are read-only mounts of existing snapshots
	viewKey := fmt.Sprintf("sbom-view-%s-%d", targetDigest[7:19], time.Now().Unix())
	mounts, err := snapshotter.View(ctx, viewKey, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to create view snapshot: %w", err)
	}

	// Ensure cleanup of view snapshot
	defer func() {
		if removeErr := snapshotter.Remove(ctx, viewKey); removeErr != nil {
			log.Printf("Warning: failed to remove view snapshot %s: %v", viewKey, removeErr)
		}
	}()

	// Mount to a temporary directory
	mountDir := fmt.Sprintf("/tmp/sbom-mount-%s", targetDigest[7:19])
	if err := os.MkdirAll(mountDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create mount directory: %w", err)
	}

	// Ensure cleanup of mount directory
	defer func() {
		if unmountErr := mount.UnmountAll(mountDir, 0); unmountErr != nil {
			log.Printf("Warning: failed to unmount %s: %v", mountDir, unmountErr)
		}
		if removeErr := os.RemoveAll(mountDir); removeErr != nil {
			log.Printf("Warning: failed to remove mount directory %s: %v", mountDir, removeErr)
		}
	}()

	// Perform the mount
	log.Printf("Mounting snapshot to: %s", mountDir)
	if err := mount.All(mounts, mountDir); err != nil {
		return nil, fmt.Errorf("failed to mount snapshot: %w", err)
	}

	// Scan the mounted filesystem with syft
	log.Printf("Scanning mounted filesystem: %s", mountDir)
	src, err := syft.GetSource(ctx, mountDir, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get source for mounted directory %s: %w", mountDir, err)
	}

	// Ensure cleanup of source
	defer func() {
		if cleanupErr := src.Close(); cleanupErr != nil {
			log.Printf("Warning: failed to cleanup source: %v", cleanupErr)
		}
	}()

	// Create SBOM from the source
	s, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM from mounted directory %s: %w", mountDir, err)
	}

	// Encode to syft JSON format
	encoder := syftjson.NewFormatEncoder()
	sbomBytes, err := format.Encode(*s, encoder)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM to JSON: %w", err)
	}

	// Get architecture from image config and inject into SBOM
	// Since we scan a mounted directory, syft doesn't have access to image metadata
	arch, os := c.getImagePlatform(ctx, img)
	if arch != "" {
		sbomBytes, err = injectPlatformIntoSBOM(sbomBytes, arch, os)
		if err != nil {
			log.Printf("Warning: failed to inject platform into SBOM: %v", err)
			// Continue with original SBOM
		} else {
			log.Printf("Injected platform into SBOM: arch=%s, os=%s", arch, os)
		}
	}

	log.Printf("Successfully generated SBOM for %s (%d bytes, %d packages)",
		imageRef, len(sbomBytes), s.Artifacts.Packages.PackageCount())

	return sbomBytes, nil
}

// getImagePlatform extracts architecture and OS from image config
func (c *ContainerDClient) getImagePlatform(ctx context.Context, img containerd.Image) (arch, os string) {
	// Get the image config which contains platform info
	configDesc, err := img.Config(ctx)
	if err != nil {
		log.Printf("Warning: failed to get image config: %v", err)
		return "", ""
	}

	// Read the config blob
	contentStore := c.client.ContentStore()
	configBlob, err := contentStore.ReaderAt(ctx, configDesc)
	if err != nil {
		log.Printf("Warning: failed to read config blob: %v", err)
		return "", ""
	}
	defer func() { _ = configBlob.Close() }()

	configData := make([]byte, configDesc.Size)
	if _, err := configBlob.ReadAt(configData, 0); err != nil {
		log.Printf("Warning: failed to read config data: %v", err)
		return "", ""
	}

	// Parse OCI image config
	var imgConfig ocispec.Image
	if err := json.Unmarshal(configData, &imgConfig); err != nil {
		log.Printf("Warning: failed to parse image config: %v", err)
		return "", ""
	}

	return imgConfig.Architecture, imgConfig.OS
}

// injectPlatformIntoSBOM modifies the SBOM JSON to include architecture and OS
// in source.metadata, matching the format syft uses for image scans
func injectPlatformIntoSBOM(sbomBytes []byte, arch, os string) ([]byte, error) {
	var sbom map[string]interface{}
	if err := json.Unmarshal(sbomBytes, &sbom); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM: %w", err)
	}

	// Get or create source.metadata
	source, ok := sbom["source"].(map[string]interface{})
	if !ok {
		source = make(map[string]interface{})
		sbom["source"] = source
	}

	metadata, ok := source["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
		source["metadata"] = metadata
	}

	// Inject architecture and OS
	metadata["architecture"] = arch
	if os != "" {
		metadata["os"] = os
	}

	// Re-encode
	return json.Marshal(sbom)
}

// Close closes the ContainerD client
func (c *ContainerDClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}
