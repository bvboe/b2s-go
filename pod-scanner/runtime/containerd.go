package runtime

import (
	"context"
	"crypto/sha256"
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

	// Note: SQLite driver is already imported transitively by syft for RPM database parsing
)

const (
	// ContainerD default socket path
	containerdSocket = "/run/containerd/containerd.sock"
	// Default namespace for Kubernetes
	k8sNamespace = "k8s.io"
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
	client *containerd.Client
}

// NewContainerDClient creates a new ContainerD runtime client
func NewContainerDClient() *ContainerDClient {
	client, err := containerd.New(containerdSocket)
	if err != nil {
		log.Printf("Failed to create ContainerD client: %v", err)
		return &ContainerDClient{client: nil}
	}
	return &ContainerDClient{client: client}
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
				if len(img.Name) > 6 && (
					(len(img.Name) >= 10 && img.Name[len(img.Name)-10:] == "-arm64:") ||
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

	log.Printf("Successfully generated SBOM for %s (%d bytes, %d packages)",
		imageRef, len(sbomBytes), s.Artifacts.Packages.PackageCount())

	return sbomBytes, nil
}

// Close closes the ContainerD client
func (c *ContainerDClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}
