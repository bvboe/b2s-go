package containers

// ContainerInstanceID identifies a specific container instance
type ContainerInstanceID struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
}

// ImageID identifies a container image
type ImageID struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"` // SHA256 digest (e.g., sha256:abc123...)
}

// ContainerInstance represents a running container instance in the cluster
type ContainerInstance struct {
	ID    ContainerInstanceID `json:"id"`
	Image ImageID             `json:"image"`
}

// ContainerInstanceCollection represents a collection of container instances
type ContainerInstanceCollection struct {
	Instances []ContainerInstance `json:"instances"`
}
