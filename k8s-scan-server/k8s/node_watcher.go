package k8s

import (
	"context"
	"log"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/nodes"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// extractNodeInfo extracts node information from a Kubernetes node object
func extractNodeInfo(node *corev1.Node) nodes.Node {
	n := nodes.Node{
		Name: node.Name,
	}

	// Extract hostname from labels or node info
	if hostname, ok := node.Labels["kubernetes.io/hostname"]; ok {
		n.Hostname = hostname
	}

	// Extract OS information from node status
	if node.Status.NodeInfo.OSImage != "" {
		n.OSRelease = node.Status.NodeInfo.OSImage
	}

	// Extract kernel version
	if node.Status.NodeInfo.KernelVersion != "" {
		n.KernelVersion = node.Status.NodeInfo.KernelVersion
	}

	// Extract architecture
	if node.Status.NodeInfo.Architecture != "" {
		n.Architecture = node.Status.NodeInfo.Architecture
	}

	// Extract container runtime
	if node.Status.NodeInfo.ContainerRuntimeVersion != "" {
		n.ContainerRuntime = node.Status.NodeInfo.ContainerRuntimeVersion
	}

	// Extract kubelet version
	if node.Status.NodeInfo.KubeletVersion != "" {
		n.KubeletVersion = node.Status.NodeInfo.KubeletVersion
	}

	return n
}

// isNodeReady checks if a node is in Ready condition
func isNodeReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

// WatchNodes watches for node changes using a SharedIndexInformer and updates the node manager.
// This implementation provides:
// - Automatic watch resumption with resourceVersion tracking (no missed events on reconnect)
// - Periodic resync to ensure eventual consistency (every 5 minutes)
// - Built-in exponential backoff on errors
// - Local cache to reduce API server load
// - Proper deletion handling even if watch connection drops
func WatchNodes(ctx context.Context, clientset kubernetes.Interface, manager *nodes.Manager) {
	// Create informer factory with 5-minute resync period
	// Resync ensures we eventually catch up even if watch events are missed
	resyncPeriod := 5 * time.Minute
	factory := informers.NewSharedInformerFactory(clientset, resyncPeriod)

	// Get the node informer
	nodeInformer := factory.Core().V1().Nodes().Informer()

	// Add event handlers
	_, err := nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				log.Printf("Unexpected object type in AddFunc: %T", obj)
				return
			}
			handleNodeAddOrUpdate(node, manager)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			node, ok := newObj.(*corev1.Node)
			if !ok {
				log.Printf("Unexpected object type in UpdateFunc: %T", newObj)
				return
			}
			handleNodeAddOrUpdate(node, manager)
		},
		DeleteFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				// Handle tombstone (object deleted from cache but we got notification late)
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					log.Printf("Unexpected object type in DeleteFunc: %T", obj)
					return
				}
				node, ok = tombstone.Obj.(*corev1.Node)
				if !ok {
					log.Printf("Tombstone contained unexpected object: %T", tombstone.Obj)
					return
				}
			}
			handleNodeDelete(node, manager)
		},
	})
	if err != nil {
		log.Printf("Error adding event handler: %v", err)
		return
	}

	log.Println("Starting node informer...")

	// Start the informer (runs in background goroutine)
	go factory.Start(ctx.Done())

	// Wait for cache to sync before considering the informer ready
	log.Println("Waiting for node informer cache to sync...")
	if !cache.WaitForCacheSync(ctx.Done(), nodeInformer.HasSynced) {
		log.Println("Failed to sync node informer cache")
		return
	}

	log.Println("Node informer cache synced and ready")

	// Block until context is cancelled
	<-ctx.Done()
	log.Println("Node watcher shutting down")
}

// handleNodeAddOrUpdate processes node additions and updates
func handleNodeAddOrUpdate(node *corev1.Node, manager *nodes.Manager) {
	// Only process ready nodes
	if isNodeReady(node) {
		nodeInfo := extractNodeInfo(node)
		manager.AddNode(nodeInfo)
	} else {
		// If node is not ready, we might want to track it differently
		// For now, just log it
		log.Printf("Skipping non-ready node: %s", node.Name)
	}
}

// handleNodeDelete processes node deletions
func handleNodeDelete(node *corev1.Node, manager *nodes.Manager) {
	manager.RemoveNode(node.Name)
	log.Printf("Removed node: %s", node.Name)
}

// SyncInitialNodes performs an initial sync of all existing nodes.
// Note: With the informer-based WatchNodes implementation, this function is less critical
// since the informer automatically performs an initial list and sync (via cache.WaitForCacheSync).
// This function is kept for explicit synchronization use cases or testing.
func SyncInitialNodes(ctx context.Context, clientset kubernetes.Interface, manager *nodes.Manager) error {
	log.Println("Performing initial node sync...")

	nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	var allNodes []nodes.Node
	for _, node := range nodeList.Items {
		// Only track ready nodes
		if isNodeReady(&node) {
			nodeInfo := extractNodeInfo(&node)
			allNodes = append(allNodes, nodeInfo)
		}
	}

	manager.SetNodes(allNodes)
	log.Printf("Initial node sync complete: %d nodes", manager.GetNodeCount())

	return nil
}
