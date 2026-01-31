package containers

// ContainerInstanceID identifies a specific container instance
type ContainerInstanceID struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
}

// ImageID identifies a container image
type ImageID struct {
	Reference string `json:"reference"` // Original image reference (e.g., "nginx:1.21" or "nginx@sha256:abc...")
	Digest    string `json:"digest"`    // SHA256 digest (e.g., sha256:abc123...)
}

// ContainerInstance represents a running container instance in the cluster
type ContainerInstance struct {
	ID               ContainerInstanceID `json:"id"`
	Image            ImageID             `json:"image"`
	NodeName         string              `json:"node_name"`          // K8s node name (empty for agent)
	ContainerRuntime string              `json:"container_runtime"` // "docker" or "containerd"
}

// ContainerInstanceCollection represents a collection of container instances
type ContainerInstanceCollection struct {
	Instances []ContainerInstance `json:"instances"`
}
