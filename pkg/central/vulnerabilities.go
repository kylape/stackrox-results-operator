package central

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"google.golang.org/protobuf/encoding/protojson"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/kylape/stackrox-results-operator/api/security/v1alpha1"
)

// ExportImageResponse represents the response from /v1/export/images
type ExportImageResponse struct {
	Result *ExportImageResult `json:"result"`
}

type ExportImageResult struct {
	Image json.RawMessage `json:"image"`
}

// ListImageVulnerabilitiesOptions contains options for listing image vulnerabilities
type ListImageVulnerabilitiesOptions struct {
	// Namespace filter
	Namespace string
	// Minimum severity
	MinSeverity string
	// Only fixable CVEs
	FixableOnly bool
	// Max CVEs per image
	MaxCVEsPerImage int
	// Max images to return
	MaxImages int
}

// ListImageVulnerabilities fetches image vulnerability data from Central
func (c *Client) ListImages(ctx context.Context, opts ListImageVulnerabilitiesOptions) ([]*storage.Image, error) {
	log.V(1).Info("Listing image vulnerabilities from Central")

	// Build query
	query := url.Values{}

	filters := []string{}

	if opts.Namespace != "" {
		filters = append(filters, fmt.Sprintf("Namespace:%s", opts.Namespace))
	}

	if opts.MinSeverity != "" {
		filters = append(filters, fmt.Sprintf("CVE Severity:%s", opts.MinSeverity))
	}

	if opts.FixableOnly {
		filters = append(filters, "Fixable:true")
	}

	if len(filters) > 0 {
		query.Set("query", strings.Join(filters, "+"))
	}

	// Note: Export API doesn't support pagination.limit like list API
	// We'll handle limiting on the client side

	path := "/v1/export/images"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to export images")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("export images failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse newline-delimited JSON stream
	var images []*storage.Image
	scanner := bufio.NewScanner(resp.Body)

	// Increase buffer size for large scan results
	const maxScanTokenSize = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	imageCount := 0
	skippedNoScan := 0
	skippedNoResult := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Step 1: Parse wrapper JSON structure
		var exportResp ExportImageResponse
		if err := json.Unmarshal(line, &exportResp); err != nil {
			log.Error(err, "Failed to parse export image wrapper", "line", string(line[:min(len(line), 200)]))
			continue
		}

		if exportResp.Result == nil || len(exportResp.Result.Image) == 0 {
			skippedNoResult++
			continue
		}

		// Step 2: Parse the image proto from raw bytes
		img := &storage.Image{}
		if err := protojson.Unmarshal(exportResp.Result.Image, img); err != nil {
			log.Error(err, "Failed to parse image protobuf")
			continue
		}

		if img.GetId() == "" {
			skippedNoResult++
			continue
		}

		// Skip images without scan data
		scan := img.GetScan()
		if scan == nil || len(scan.GetComponents()) == 0 {
			imgName := ""
			if img.GetName() != nil {
				imgName = img.GetName().GetFullName()
			}
			log.V(1).Info("Skipping image without scan data", "imageName", imgName)
			skippedNoScan++
			continue
		}

		// Note: MaxCVEsPerImage filtering is not applied here since CVEs are nested
		// in components. Filtering would require modifying the proto, which we avoid.
		// This can be handled in the conversion layer if needed.

		images = append(images, img)
		imageCount++

		// Limit number of images if requested
		if opts.MaxImages > 0 && imageCount >= opts.MaxImages {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to read export stream")
	}

	log.Info("Retrieved image vulnerabilities from Central",
		"count", len(images),
		"skippedNoScan", skippedNoScan,
		"skippedNoResult", skippedNoResult)
	return images, nil
}

// ListNodeVulnerabilities fetches node vulnerability data from Central
func (c *Client) ListNodeVulnerabilities(ctx context.Context, minSeverity string, maxCVEsPerNode int) ([]*storage.Node, error) {
	log.V(1).Info("Listing node vulnerabilities from Central")

	// First, get all clusters
	resp, err := c.doRequest(ctx, "GET", "/v1/clusters")
	if err != nil {
		return nil, errors.Wrap(err, "failed to list clusters")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("list clusters failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read clusters response body")
	}

	var clustersResponse struct {
		Clusters []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"clusters"`
	}

	if err := json.Unmarshal(body, &clustersResponse); err != nil {
		return nil, errors.Wrap(err, "failed to parse clusters response")
	}

	// Collect all nodes from all clusters
	var allNodes []*storage.Node

	for _, cluster := range clustersResponse.Clusters {
		log.V(1).Info("Fetching nodes for cluster", "clusterID", cluster.ID, "clusterName", cluster.Name)

		// Build path with cluster ID
		path := fmt.Sprintf("/v1/nodes/%s", cluster.ID)

		// Build query for filtering
		query := url.Values{}
		if minSeverity != "" {
			severityLevels := getSeverityLevelsAbove(minSeverity)
			filters := []string{}
			for _, sev := range severityLevels {
				filters = append(filters, fmt.Sprintf("CVE Severity:%s", sev))
			}
			query.Set("query", strings.Join(filters, "+"))
		}

		if len(query) > 0 {
			path += "?" + query.Encode()
		}

		resp, err := c.doRequest(ctx, "GET", path)
		if err != nil {
			log.Info("Failed to list nodes for cluster", "clusterID", cluster.ID, "error", err.Error())
			continue // Skip this cluster on error
		}

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			log.Info("List nodes failed for cluster",
				"clusterID", cluster.ID, "status", resp.StatusCode, "body", string(body))
			resp.Body.Close()
			continue // Skip this cluster on error
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Info("Failed to read nodes response body for cluster", "clusterID", cluster.ID, "error", err.Error())
			continue // Skip this cluster on error
		}

		nodesResponse := v1.ListNodesResponse{}

		// Use protojson to unmarshal
		if err := protojson.Unmarshal(body, &nodesResponse); err != nil {
			log.Info("Failed to parse nodes response for cluster", "clusterID", cluster.ID, "error", err.Error())
			continue // Skip this cluster on error
		}

		allNodes = append(allNodes, nodesResponse.Nodes...)
	}

	// Note: maxCVEsPerNode is no longer applicable since storage.Node doesn't have a CVEs array
	// It has Components which contain vulnerabilities. Filtering would need to be done differently.
	if maxCVEsPerNode > 0 {
		log.V(1).Info("maxCVEsPerNode parameter is deprecated with storage.Node types")
	}

	log.Info("Retrieved node vulnerabilities from Central", "count", len(allNodes))
	return allNodes, nil
}

// ConvertImageToCRD converts a storage.Image to ImageVulnerability CRD
func ConvertImageToCRD(img *storage.Image, exporterName string) *securityv1alpha1.ImageVulnerability {
	vuln := &securityv1alpha1.ImageVulnerability{
		Spec:   securityv1alpha1.ImageVulnerabilitySpec{},
		Status: securityv1alpha1.ImageVulnerabilityStatus{},
	}

	// Image reference
	imageName := img.GetName()
	if imageName != nil {
		fullName := imageName.GetFullName()
		imageRef := securityv1alpha1.ImageReference{
			Name:     extractImageName(fullName),
			FullName: fullName,
			Registry: imageName.GetRegistry(),
			Remote:   imageName.GetRemote(),
			Tag:      imageName.GetTag(),
		}

		metadata := img.GetMetadata()
		if metadata != nil && metadata.GetV1() != nil {
			imageRef.SHA = metadata.GetV1().GetDigest()
		}

		vuln.Status.Image = &imageRef

		// Generate name from image
		vuln.Name = generateImageVulnName(fullName, imageRef.SHA)
	}

	// Extract CVEs and calculate summary from components
	scan := img.GetScan()
	if scan != nil {
		// Scan time
		if scanTime := scan.GetScanTime(); scanTime != nil {
			t := metav1.NewTime(scanTime.AsTime())
			vuln.Status.ScanTime = &t
		}

		// Extract scan notes
		if len(scan.GetNotes()) > 0 {
			notes := make([]string, 0, len(scan.GetNotes()))
			for _, note := range scan.GetNotes() {
				// Convert enum to string (e.g., "OS_UNAVAILABLE")
				notes = append(notes, note.String())
			}
			vuln.Status.Notes = notes
		}

		// Extract all CVEs from components
		allCVEs := make(map[string]*securityv1alpha1.CVE) // Deduplicate CVEs by ID
		criticalCount := &securityv1alpha1.SeverityCount{}
		highCount := &securityv1alpha1.SeverityCount{}
		mediumCount := &securityv1alpha1.SeverityCount{}
		lowCount := &securityv1alpha1.SeverityCount{}

		for _, component := range scan.GetComponents() {
			for _, vuln := range component.GetVulns() {
				cveID := vuln.GetCve()
				if cveID == "" {
					continue
				}

				// Add to deduped CVE map
				if _, exists := allCVEs[cveID]; !exists {
					cve := securityv1alpha1.CVE{
						CVE:      cveID,
						Link:     vuln.GetLink(),
						Severity: convertStorageSeverity(vuln.GetSeverity()),
						Component: &securityv1alpha1.Component{
							Name:     component.GetName(),
							Version:  component.GetVersion(),
							Location: component.GetLocation(),
						},
					}

					if vuln.GetCvss() > 0 {
						cve.CVSS = fmt.Sprintf("%.1f", vuln.GetCvss())
					}

					fixedBy := vuln.GetSetFixedBy()
					if fixedBy != nil {
						if fb, ok := fixedBy.(*storage.EmbeddedVulnerability_FixedBy); ok {
							cve.FixedBy = fb.FixedBy
							cve.Fixable = fb.FixedBy != ""
						}
					}

					if cvssV3 := vuln.GetCvssV3(); cvssV3 != nil {
						cve.CVSSv3 = &securityv1alpha1.CVSSv3{
							Score:  fmt.Sprintf("%.1f", cvssV3.GetScore()),
							Vector: cvssV3.GetVector(),
						}
					}

					if epss := vuln.GetEpss(); epss != nil {
						cve.EPSS = &securityv1alpha1.EPSS{
							Score:      fmt.Sprintf("%.5f", epss.GetEpssProbability()),
							Percentile: fmt.Sprintf("%.5f", epss.GetEpssPercentile()),
						}
					}

					if publishedOn := vuln.GetPublishedOn(); publishedOn != nil {
						t := metav1.NewTime(publishedOn.AsTime())
						cve.Published = &t
					}

					if firstImageOccurrence := vuln.GetFirstImageOccurrence(); firstImageOccurrence != nil {
						t := metav1.NewTime(firstImageOccurrence.AsTime())
						cve.DiscoveredInImage = &t
					}

					cve.State = convertVulnerabilityState(vuln.GetState())

					allCVEs[cveID] = &cve
				}

				// Count by severity for summary
				fixable := false
				if fb := vuln.GetSetFixedBy(); fb != nil {
					if fixed, ok := fb.(*storage.EmbeddedVulnerability_FixedBy); ok {
						fixable = fixed.FixedBy != ""
					}
				}

				switch vuln.GetSeverity() {
				case storage.VulnerabilitySeverity_CRITICAL_VULNERABILITY_SEVERITY:
					criticalCount.Total++
					if fixable {
						criticalCount.Fixable++
					}
				case storage.VulnerabilitySeverity_IMPORTANT_VULNERABILITY_SEVERITY:
					highCount.Total++
					if fixable {
						highCount.Fixable++
					}
				case storage.VulnerabilitySeverity_MODERATE_VULNERABILITY_SEVERITY:
					mediumCount.Total++
					if fixable {
						mediumCount.Fixable++
					}
				case storage.VulnerabilitySeverity_LOW_VULNERABILITY_SEVERITY:
					lowCount.Total++
					if fixable {
						lowCount.Fixable++
					}
				}
			}
		}

		// Convert map to slice
		cveSlice := make([]securityv1alpha1.CVE, 0, len(allCVEs))
		for _, cve := range allCVEs {
			cveSlice = append(cveSlice, *cve)
		}
		vuln.Status.CVEs = cveSlice

		// Build summary
		summary := securityv1alpha1.VulnerabilitySummary{
			Total:        criticalCount.Total + highCount.Total + mediumCount.Total + lowCount.Total,
			FixableTotal: criticalCount.Fixable + highCount.Fixable + mediumCount.Fixable + lowCount.Fixable,
		}
		if criticalCount.Total > 0 {
			summary.Critical = criticalCount
		}
		if highCount.Total > 0 {
			summary.High = highCount
		}
		if mediumCount.Total > 0 {
			summary.Medium = mediumCount
		}
		if lowCount.Total > 0 {
			summary.Low = lowCount
		}
		vuln.Status.Summary = &summary
	}

	// Labels
	if vuln.Status.Image != nil {
		vuln.Labels = map[string]string{
			"app.kubernetes.io/managed-by": "results-operator",
			"results.stackrox.io/exporter": exporterName,
			"stackrox.io/image-name":       sanitizeLabelValue(vuln.Status.Image.Name),
		}

		if vuln.Status.Image.Tag != "" {
			vuln.Labels["stackrox.io/image-tag"] = sanitizeLabelValue(vuln.Status.Image.Tag)
		}

		if vuln.Status.Image.Registry != "" {
			vuln.Labels["stackrox.io/registry"] = sanitizeLabelValue(vuln.Status.Image.Registry)
		}
	}

	// Add severity labels
	if vuln.Status.Summary != nil {
		if vuln.Status.Summary.Critical != nil && vuln.Status.Summary.Critical.Total > 0 {
			vuln.Labels["stackrox.io/has-critical"] = "true"
		}
		if vuln.Status.Summary.FixableTotal > 0 {
			vuln.Labels["stackrox.io/has-fixable"] = "true"
		}
	}

	return vuln
}

// ConvertNodeToCRD converts a storage.Node to NodeVulnerability CRD
func ConvertNodeToCRD(node *storage.Node, exporterName string) *securityv1alpha1.NodeVulnerability {
	vuln := &securityv1alpha1.NodeVulnerability{
		Spec: securityv1alpha1.NodeVulnerabilitySpec{},
		Status: securityv1alpha1.NodeVulnerabilityStatus{
			NodeName:      node.GetName(),
			OSImage:       node.GetOsImage(),
			KernelVersion: node.GetKernelVersion(),
		},
	}

	// Generate name from node name
	vuln.Name = generateNodeVulnName(node.GetName())

	// Extract scan data
	scan := node.GetScan()
	if scan != nil {
		// Scan time
		if scanTime := scan.GetScanTime(); scanTime != nil {
			t := metav1.NewTime(scanTime.AsTime())
			vuln.Status.ScanTime = &t
		}

		// Extract CVEs and calculate summary from components
		allCVEs := make(map[string]*securityv1alpha1.CVE) // Deduplicate CVEs by ID
		criticalCount := &securityv1alpha1.SeverityCount{}
		highCount := &securityv1alpha1.SeverityCount{}
		mediumCount := &securityv1alpha1.SeverityCount{}
		lowCount := &securityv1alpha1.SeverityCount{}

		for _, component := range scan.GetComponents() {
			for _, vuln := range component.GetVulnerabilities() {
				cveID := vuln.GetCveBaseInfo().GetCve()
				if cveID == "" {
					continue
				}

				// Add to deduped CVE map
				if _, exists := allCVEs[cveID]; !exists {
					cve := securityv1alpha1.CVE{
						CVE:      cveID,
						Severity: convertStorageSeverity(vuln.GetSeverity()),
					}
					if vuln.GetCvss() > 0 {
						cve.CVSS = fmt.Sprintf("%.1f", vuln.GetCvss())
					}
					if vuln.GetFixedBy() != "" {
						cve.FixedBy = vuln.GetFixedBy()
					}
					allCVEs[cveID] = &cve
				}

				// Count by severity
				fixable := vuln.GetFixedBy() != ""
				switch vuln.GetSeverity() {
				case storage.VulnerabilitySeverity_CRITICAL_VULNERABILITY_SEVERITY:
					criticalCount.Total++
					if fixable {
						criticalCount.Fixable++
					}
				case storage.VulnerabilitySeverity_IMPORTANT_VULNERABILITY_SEVERITY:
					highCount.Total++
					if fixable {
						highCount.Fixable++
					}
				case storage.VulnerabilitySeverity_MODERATE_VULNERABILITY_SEVERITY:
					mediumCount.Total++
					if fixable {
						mediumCount.Fixable++
					}
				case storage.VulnerabilitySeverity_LOW_VULNERABILITY_SEVERITY:
					lowCount.Total++
					if fixable {
						lowCount.Fixable++
					}
				}
			}
		}

		// Convert map to slice
		cveSlice := make([]securityv1alpha1.CVE, 0, len(allCVEs))
		for _, cve := range allCVEs {
			cveSlice = append(cveSlice, *cve)
		}
		vuln.Status.CVEs = cveSlice

		// Build summary
		summary := securityv1alpha1.VulnerabilitySummary{
			Total:        criticalCount.Total + highCount.Total + mediumCount.Total + lowCount.Total,
			FixableTotal: criticalCount.Fixable + highCount.Fixable + mediumCount.Fixable + lowCount.Fixable,
		}
		if criticalCount.Total > 0 {
			summary.Critical = criticalCount
		}
		if highCount.Total > 0 {
			summary.High = highCount
		}
		if mediumCount.Total > 0 {
			summary.Medium = mediumCount
		}
		if lowCount.Total > 0 {
			summary.Low = lowCount
		}
		vuln.Status.Summary = &summary
	}

	// Labels
	vuln.Labels = map[string]string{
		"app.kubernetes.io/managed-by": "results-operator",
		"results.stackrox.io/exporter": exporterName,
		"stackrox.io/node-name":        sanitizeLabelValue(node.GetName()),
	}

	if vuln.Status.Summary != nil && vuln.Status.Summary.Critical != nil && vuln.Status.Summary.Critical.Total > 0 {
		vuln.Labels["stackrox.io/has-critical"] = "true"
	}

	return vuln
}

// convertStorageSeverity converts storage.VulnerabilitySeverity to string
func convertStorageSeverity(severity storage.VulnerabilitySeverity) string {
	switch severity {
	case storage.VulnerabilitySeverity_CRITICAL_VULNERABILITY_SEVERITY:
		return "CRITICAL"
	case storage.VulnerabilitySeverity_IMPORTANT_VULNERABILITY_SEVERITY:
		return "HIGH"
	case storage.VulnerabilitySeverity_MODERATE_VULNERABILITY_SEVERITY:
		return "MEDIUM"
	case storage.VulnerabilitySeverity_LOW_VULNERABILITY_SEVERITY:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// convertVulnerabilityState converts storage.VulnerabilityState to string
func convertVulnerabilityState(state storage.VulnerabilityState) string {
	switch state {
	case storage.VulnerabilityState_OBSERVED:
		return "OBSERVED"
	case storage.VulnerabilityState_DEFERRED:
		return "DEFERRED"
	case storage.VulnerabilityState_FALSE_POSITIVE:
		return "FALSE_POSITIVE"
	default:
		return ""
	}
}

// Helper functions

func extractImageName(fullName string) string {
	// Extract just the image name from full name
	// e.g., "docker.io/library/nginx:1.25.3" -> "nginx"
	parts := strings.Split(fullName, "/")
	lastPart := parts[len(parts)-1]

	// Remove tag
	nameParts := strings.Split(lastPart, ":")
	return nameParts[0]
}

func generateImageVulnName(fullName, sha string) string {
	// Generate Kubernetes-friendly name
	name := extractImageName(fullName)
	tag := ""

	// Extract tag
	parts := strings.Split(fullName, ":")
	if len(parts) > 1 {
		tag = parts[len(parts)-1]
		// Remove any digest
		tag = strings.Split(tag, "@")[0]
	}

	// Clean up - remove all invalid Kubernetes name characters
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, ".", "-")
	name = strings.ReplaceAll(name, "@", "-")

	tag = strings.ToLower(tag)
	tag = strings.ReplaceAll(tag, ".", "-")
	tag = strings.ReplaceAll(tag, "@", "-")

	// Use short SHA
	shortSHA := ""
	if sha != "" {
		// Remove "sha256:" prefix if present
		sha = strings.TrimPrefix(sha, "sha256:")
		if len(sha) > 12 {
			shortSHA = sha[:12]
		} else {
			shortSHA = sha
		}
	}

	// Combine: <name>-<tag>-sha256-<short-sha>
	if tag != "" && shortSHA != "" {
		return fmt.Sprintf("%s-%s-sha256-%s", name, tag, shortSHA)
	} else if tag != "" {
		return fmt.Sprintf("%s-%s", name, tag)
	} else if shortSHA != "" {
		return fmt.Sprintf("%s-sha256-%s", name, shortSHA)
	}

	return name
}

func generateNodeVulnName(nodeName string) string {
	// Generate Kubernetes-friendly name from node name
	name := strings.ToLower(nodeName)
	name = strings.ReplaceAll(name, ".", "-")
	name = strings.ReplaceAll(name, "_", "-")

	return fmt.Sprintf("node-%s", name)
}
