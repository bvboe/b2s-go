package docker

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// parseImageName parses a container image string into repository and tag
// Example: "nginx:1.21" -> repository="nginx", tag="1.21"
// Example: "docker.io/library/nginx:1.21" -> repository="docker.io/library/nginx", tag="1.21"
func parseImageName(imageName string) (repository, tag string) {
	// Split by '@' first to handle digest
	parts := strings.Split(imageName, "@")
	imageName = parts[0]

	// Split by ':' to separate tag
	parts = strings.Split(imageName, ":")
	repository = parts[0]
	if len(parts) > 1 {
		tag = parts[1]
	} else {
		tag = "latest"
	}
	return
}

// extractContainerInstance creates a ContainerInstance from Docker container info
func extractContainerInstance(ctx context.Context, cli *client.Client, containerID string) (containers.ContainerInstance, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	// Get detailed container info
	containerJSON, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return containers.ContainerInstance{}, err
	}

	repository, tag := parseImageName(containerJSON.Config.Image)

	// Extract image digest from RepoDigests if available
	digest := ""
	if len(containerJSON.Image) > 0 {
		// The Image field contains the image ID (sha256:...)
		digest = containerJSON.Image
	}

	// Use container name (remove leading /)
	containerName := strings.TrimPrefix(containerJSON.Name, "/")
	if containerName == "" {
		containerName = containerID[:12] // Use short container ID as fallback
	}

	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: hostname,
			Pod:       "host", // Indicate this is a host-level container
			Container: containerName,
		},
		Image: containers.ImageID{
			Repository: repository,
			Tag:        tag,
			Digest:     digest,
		},
	}

	return instance, nil
}

// IsDockerAvailable checks if Docker daemon is accessible
func IsDockerAvailable() bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return false
	}
	defer func() { _ = cli.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = cli.Ping(ctx)
	return err == nil
}

// WatchContainers watches for Docker container events and updates the container manager
func WatchContainers(ctx context.Context, manager *containers.Manager) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer func() { _ = cli.Close() }()

	// Test connection
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = cli.Ping(pingCtx)
	cancel()
	if err != nil {
		return err
	}

	log.Println("Docker watcher: connected to Docker daemon")

	// Perform initial sync of running containers
	if err := syncInitialContainers(ctx, cli, manager); err != nil {
		log.Printf("Warning: initial container sync failed: %v", err)
	}

	// Start watching for events
	for {
		select {
		case <-ctx.Done():
			log.Println("Docker watcher shutting down")
			return nil
		default:
			// Watch for container events
			eventFilters := filters.NewArgs()
			eventFilters.Add("type", "container")

			eventsChan, errChan := cli.Events(ctx, events.ListOptions{
				Filters: eventFilters,
			})

			log.Println("Docker watcher started")

		eventLoop:
			for {
				select {
				case <-ctx.Done():
					log.Println("Docker watcher shutting down")
					return nil

				case err := <-errChan:
					if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
						log.Printf("Docker events error: %v", err)
					}
					break eventLoop

				case event := <-eventsChan:
					switch event.Action {
					case "start":
						// Container started
						instance, err := extractContainerInstance(ctx, cli, event.Actor.ID)
						if err != nil {
							log.Printf("Error extracting container instance for %s: %v", event.Actor.ID[:12], err)
							continue
						}
						manager.AddContainerInstance(instance)

					case "die", "kill", "stop":
						// Container stopped - we need to get the container info before it's removed
						instance, err := extractContainerInstance(ctx, cli, event.Actor.ID)
						if err != nil {
							// Container might already be removed, use event data
							hostname, _ := os.Hostname()
							if hostname == "" {
								hostname = "unknown"
							}
							containerName := event.Actor.Attributes["name"]
							if containerName == "" {
								containerName = event.Actor.ID[:12]
							}
							instance = containers.ContainerInstance{
								ID: containers.ContainerInstanceID{
									Namespace: hostname,
									Pod:       "host",
									Container: containerName,
								},
							}
						}
						manager.RemoveContainerInstance(instance.ID)
					}
				}
			}

			log.Println("Docker watcher connection closed, reconnecting...")
			time.Sleep(1 * time.Second)
		}
	}
}

// syncInitialContainers performs an initial sync of all running containers
func syncInitialContainers(ctx context.Context, cli *client.Client, manager *containers.Manager) error {
	log.Println("Docker watcher: performing initial container sync...")

	containerList, err := cli.ContainerList(ctx, containertypes.ListOptions{
		All: false, // Only running containers
	})
	if err != nil {
		return err
	}

	var allInstances []containers.ContainerInstance
	for _, container := range containerList {
		instance, err := extractContainerInstance(ctx, cli, container.ID)
		if err != nil {
			log.Printf("Warning: failed to extract container %s: %v", container.ID[:12], err)
			continue
		}
		allInstances = append(allInstances, instance)
	}

	manager.SetContainerInstances(allInstances)
	log.Printf("Docker watcher: initial sync complete: %d container instances", manager.GetInstanceCount())

	return nil
}
