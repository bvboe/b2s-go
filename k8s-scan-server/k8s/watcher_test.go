package k8s

import (
	"testing"
)

func TestParseImageName(t *testing.T) {
	tests := []struct {
		name           string
		imageName      string
		wantRepository string
		wantTag        string
	}{
		{
			name:           "simple image with tag",
			imageName:      "nginx:1.21",
			wantRepository: "nginx",
			wantTag:        "1.21",
		},
		{
			name:           "simple image without tag defaults to latest",
			imageName:      "nginx",
			wantRepository: "nginx",
			wantTag:        "latest",
		},
		{
			name:           "fully qualified image with tag",
			imageName:      "docker.io/library/nginx:1.21",
			wantRepository: "docker.io/library/nginx",
			wantTag:        "1.21",
		},
		{
			name:           "gcr image with tag",
			imageName:      "gcr.io/myproject/myimage:v1.2.3",
			wantRepository: "gcr.io/myproject/myimage",
			wantTag:        "v1.2.3",
		},
		{
			name:           "image with digest is stripped",
			imageName:      "nginx:1.21@sha256:abc123",
			wantRepository: "nginx",
			wantTag:        "1.21",
		},
		{
			name:           "image with only digest and no tag",
			imageName:      "nginx@sha256:abc123",
			wantRepository: "nginx",
			wantTag:        "latest",
		},
		{
			name:           "image with port in registry",
			imageName:      "localhost:5000/myimage:latest",
			wantRepository: "localhost:5000/myimage",
			wantTag:        "latest",
		},
		{
			name:           "empty string",
			imageName:      "",
			wantRepository: "",
			wantTag:        "latest",
		},
		{
			name:           "image with multiple path components",
			imageName:      "registry.k8s.io/kube-proxy:v1.28.0",
			wantRepository: "registry.k8s.io/kube-proxy",
			wantTag:        "v1.28.0",
		},
		{
			name:           "image with sha1 tag",
			imageName:      "myimage:abc123def456",
			wantRepository: "myimage",
			wantTag:        "abc123def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRepository, gotTag := parseImageName(tt.imageName)
			if gotRepository != tt.wantRepository {
				t.Errorf("parseImageName() repository = %v, want %v", gotRepository, tt.wantRepository)
			}
			if gotTag != tt.wantTag {
				t.Errorf("parseImageName() tag = %v, want %v", gotTag, tt.wantTag)
			}
		})
	}
}

func TestExtractDigestFromImageID(t *testing.T) {
	tests := []struct {
		name       string
		imageID    string
		wantDigest string
	}{
		{
			name:       "full ImageID with repository and digest",
			imageID:    "docker.io/library/nginx@sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
			wantDigest: "sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
		},
		{
			name:       "ImageID with short repository",
			imageID:    "nginx@sha256:abc123def456",
			wantDigest: "sha256:abc123def456",
		},
		{
			name:       "just digest without repository",
			imageID:    "sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
			wantDigest: "sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
		},
		{
			name:       "empty string",
			imageID:    "",
			wantDigest: "",
		},
		{
			name:       "ImageID without digest",
			imageID:    "nginx:1.21",
			wantDigest: "",
		},
		{
			name:       "ImageID with registry and digest",
			imageID:    "gcr.io/myproject/myimage@sha256:1234567890abcdef",
			wantDigest: "sha256:1234567890abcdef",
		},
		{
			name:       "ImageID with localhost registry",
			imageID:    "localhost:5000/myimage@sha256:fedcba0987654321",
			wantDigest: "sha256:fedcba0987654321",
		},
		{
			name:       "malformed ImageID with multiple @ symbols takes first digest",
			imageID:    "registry.io/image@sha256:abc@extra",
			wantDigest: "sha256:abc",
		},
		{
			name:       "ImageID with sha512 digest",
			imageID:    "myimage@sha512:abcdef123456",
			wantDigest: "sha512:abcdef123456",
		},
		{
			name:       "just repository without digest",
			imageID:    "docker.io/library/nginx",
			wantDigest: "",
		},
		{
			name:       "ImageID with tag and digest",
			imageID:    "nginx:1.21@sha256:abc123",
			wantDigest: "sha256:abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDigest := extractDigestFromImageID(tt.imageID)
			if gotDigest != tt.wantDigest {
				t.Errorf("extractDigestFromImageID() = %v, want %v", gotDigest, tt.wantDigest)
			}
		})
	}
}

// TestParseImageNameAndExtractDigest tests the combination of both functions
// to ensure they work correctly together as used in extractContainerInstances
func TestParseImageNameAndExtractDigest(t *testing.T) {
	tests := []struct {
		name           string
		containerImage string // from pod.spec.containers[].image
		statusImageID  string // from pod.status.containerStatuses[].imageID
		wantRepository string
		wantTag        string
		wantDigest     string
	}{
		{
			name:           "typical Kubernetes pod status",
			containerImage: "nginx:1.21",
			statusImageID:  "docker.io/library/nginx@sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
			wantRepository: "nginx",
			wantTag:        "1.21",
			wantDigest:     "sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
		},
		{
			name:           "image without tag, status with digest",
			containerImage: "nginx",
			statusImageID:  "docker.io/library/nginx@sha256:abc123",
			wantRepository: "nginx",
			wantTag:        "latest",
			wantDigest:     "sha256:abc123",
		},
		{
			name:           "fully qualified image with private registry",
			containerImage: "gcr.io/myproject/myimage:v1.0.0",
			statusImageID:  "gcr.io/myproject/myimage@sha256:def456",
			wantRepository: "gcr.io/myproject/myimage",
			wantTag:        "v1.0.0",
			wantDigest:     "sha256:def456",
		},
		{
			name:           "pending pod without status",
			containerImage: "nginx:1.21",
			statusImageID:  "",
			wantRepository: "nginx",
			wantTag:        "1.21",
			wantDigest:     "",
		},
		{
			name:           "image specified by digest",
			containerImage: "nginx@sha256:original123",
			statusImageID:  "docker.io/library/nginx@sha256:actual456",
			wantRepository: "nginx",
			wantTag:        "latest",
			wantDigest:     "sha256:actual456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate what happens in extractContainerInstances
			gotRepository, gotTag := parseImageName(tt.containerImage)
			gotDigest := extractDigestFromImageID(tt.statusImageID)

			if gotRepository != tt.wantRepository {
				t.Errorf("repository = %v, want %v", gotRepository, tt.wantRepository)
			}
			if gotTag != tt.wantTag {
				t.Errorf("tag = %v, want %v", gotTag, tt.wantTag)
			}
			if gotDigest != tt.wantDigest {
				t.Errorf("digest = %v, want %v", gotDigest, tt.wantDigest)
			}
		})
	}
}
