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

	securityv1alpha1 "github.com/kylape/stackrox-results-operator/api/security/v1alpha1"
)

// ExportImageResponse represents the response from /v1/export/images
type ExportImageResponse struct {
	Result *ExportImageResult `json:"result"`
}

type ExportImageResult struct {
	Image *StorageImage `json:"image"`
}

// StorageImage represents the full image object from the export API
type StorageImage struct {
	ID       string         `json:"id"`
	Name     *ImageName     `json:"name"`
	Metadata *ImageMetadata `json:"metadata,omitempty"`
	Scan     *ImageScanData `json:"scan,omitempty"`
}

// ImageScanData represents scan results from the export API
type ImageScanData struct {
	ScannerVersion string       `json:"scannerVersion,omitempty"`
	ScanTime       string       `json:"scanTime"`
	Components     []*Component `json:"components,omitempty"`
}

// ImageScan represents an image scan result (legacy structure for compatibility)
type ImageScan struct {
	Image      *Image       `json:"image"`
	ScanTime   string       `json:"scanTime"`
	Components []*Component `json:"components,omitempty"`
	CVEs       []*CVE       `json:"cves,omitempty"`
	Summary    *VulnSummary `json:"summary,omitempty"`
}

type Image struct {
	ID       string         `json:"id"`
	Name     *ImageName     `json:"name"`
	Metadata *ImageMetadata `json:"metadata,omitempty"`
}

type ImageName struct {
	Registry string `json:"registry,omitempty"`
	Remote   string `json:"remote,omitempty"`
	Tag      string `json:"tag,omitempty"`
	FullName string `json:"fullName,omitempty"`
}

type ImageMetadata struct {
	V1 *V1Metadata `json:"v1,omitempty"`
}

type V1Metadata struct {
	Digest string `json:"digest,omitempty"`
}

type Component struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Location string `json:"location,omitempty"`
	Vulns    []*CVE `json:"vulns,omitempty"`
}

type CVE struct {
	CVE               string     `json:"cve"`
	Summary           string     `json:"summary,omitempty"`
	Link              string     `json:"link,omitempty"`
	Severity          string     `json:"severity"`
	CVSS              string     `json:"cvss,omitempty"`
	CVSSv3            *CVSSv3    `json:"cvssV3,omitempty"`
	Component         *Component `json:"component,omitempty"`
	Fixable           bool       `json:"fixable,omitempty"`
	FixedBy           string     `json:"fixedBy,omitempty"`
	Published         string     `json:"publishedOn,omitempty"`
	DiscoveredInImage string     `json:"discoveredInImage,omitempty"`
	State             string     `json:"state,omitempty"`
	EPSS              *EPSS      `json:"epss,omitempty"`
}

type CVSSv3 struct {
	Score  string `json:"score"`
	Vector string `json:"vector"`
}

type EPSS struct {
	Score      string `json:"score"`
	Percentile string `json:"percentile"`
}

type VulnSummary struct {
	TotalCVEs        int            `json:"totalCves,omitempty"`
	FixableCVEs      int            `json:"fixableCves,omitempty"`
	CriticalSeverity *SeverityCount `json:"criticalSeverity,omitempty"`
	HighSeverity     *SeverityCount `json:"highSeverity,omitempty"`
	MediumSeverity   *SeverityCount `json:"mediumSeverity,omitempty"`
	LowSeverity      *SeverityCount `json:"lowSeverity,omitempty"`
}

type SeverityCount struct {
	Total   int `json:"total"`
	Fixable int `json:"fixable"`
}

// NodeScan represents a node scan result from Central
type NodeScan struct {
	NodeName      string       `json:"nodeName"`
	OSImage       string       `json:"osImage,omitempty"`
	KernelVersion string       `json:"kernelVersion,omitempty"`
	ScanTime      string       `json:"scanTime"`
	CVEs          []*CVE       `json:"cves,omitempty"`
	Summary       *VulnSummary `json:"summary,omitempty"`
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
func (c *Client) ListImageVulnerabilities(ctx context.Context, opts ListImageVulnerabilitiesOptions) ([]*ImageScan, error) {
	log.V(1).Info("Listing image vulnerabilities from Central")

	// Build query
	query := url.Values{}

	filters := []string{}

	if opts.Namespace != "" {
		filters = append(filters, fmt.Sprintf("Namespace:%s", opts.Namespace))
	}

	if opts.MinSeverity != "" {
		severityLevels := getSeverityLevelsAbove(opts.MinSeverity)
		for _, sev := range severityLevels {
			filters = append(filters, fmt.Sprintf("CVE Severity:%s", sev))
		}
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
	var imageScans []*ImageScan
	scanner := bufio.NewScanner(resp.Body)

	// Increase buffer size for large scan results
	const maxScanTokenSize = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	imageCount := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var exportResp ExportImageResponse
		if err := json.Unmarshal(line, &exportResp); err != nil {
			log.Error(err, "Failed to parse export image response", "line", string(line))
			continue
		}

		if exportResp.Result == nil || exportResp.Result.Image == nil {
			continue
		}

		img := exportResp.Result.Image

		// Skip images without scan data
		if img.Scan == nil || len(img.Scan.Components) == 0 {
			continue
		}

		// Convert to ImageScan format
		imageScan := convertStorageImageToImageScan(img)

		// Apply filters
		if opts.MaxCVEsPerImage > 0 && len(imageScan.CVEs) > opts.MaxCVEsPerImage {
			imageScan.CVEs = imageScan.CVEs[:opts.MaxCVEsPerImage]
		}

		imageScans = append(imageScans, imageScan)
		imageCount++

		// Limit number of images if requested
		if opts.MaxImages > 0 && imageCount >= opts.MaxImages {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to read export stream")
	}

	log.Info("Retrieved image vulnerabilities from Central", "count", len(imageScans))
	return imageScans, nil
}

// convertStorageImageToImageScan converts the export API format to ImageScan format
func convertStorageImageToImageScan(img *StorageImage) *ImageScan {
	scan := &ImageScan{
		Image: &Image{
			ID:       img.ID,
			Name:     img.Name,
			Metadata: img.Metadata,
		},
	}

	if img.Scan != nil {
		scan.ScanTime = img.Scan.ScanTime
		scan.Components = img.Scan.Components

		// Extract CVEs from components
		var allCVEs []*CVE
		for _, comp := range img.Scan.Components {
			for _, vuln := range comp.Vulns {
				// Set component reference on the CVE
				if vuln.Component == nil {
					vuln.Component = &Component{
						Name:     comp.Name,
						Version:  comp.Version,
						Location: comp.Location,
					}
				}
				allCVEs = append(allCVEs, vuln)
			}
		}
		scan.CVEs = allCVEs

		// Calculate summary
		scan.Summary = calculateVulnSummary(allCVEs)
	}

	return scan
}

// calculateVulnSummary generates a vulnerability summary from CVEs
func calculateVulnSummary(cves []*CVE) *VulnSummary {
	summary := &VulnSummary{
		CriticalSeverity: &SeverityCount{},
		HighSeverity:     &SeverityCount{},
		MediumSeverity:   &SeverityCount{},
		LowSeverity:      &SeverityCount{},
	}

	for _, cve := range cves {
		summary.TotalCVEs++
		if cve.Fixable {
			summary.FixableCVEs++
		}

		severity := strings.ToUpper(cve.Severity)
		switch severity {
		case "CRITICAL", "CRITICAL_VULNERABILITY_SEVERITY":
			summary.CriticalSeverity.Total++
			if cve.Fixable {
				summary.CriticalSeverity.Fixable++
			}
		case "HIGH", "IMPORTANT", "IMPORTANT_VULNERABILITY_SEVERITY":
			summary.HighSeverity.Total++
			if cve.Fixable {
				summary.HighSeverity.Fixable++
			}
		case "MEDIUM", "MODERATE", "MODERATE_VULNERABILITY_SEVERITY":
			summary.MediumSeverity.Total++
			if cve.Fixable {
				summary.MediumSeverity.Fixable++
			}
		case "LOW", "LOW_VULNERABILITY_SEVERITY":
			summary.LowSeverity.Total++
			if cve.Fixable {
				summary.LowSeverity.Fixable++
			}
		}
	}

	return summary
}

// ListNodeVulnerabilities fetches node vulnerability data from Central
func (c *Client) ListNodeVulnerabilities(ctx context.Context, minSeverity string, maxCVEsPerNode int) ([]*NodeScan, error) {
	log.V(1).Info("Listing node vulnerabilities from Central")

	// Build query
	query := url.Values{}

	if minSeverity != "" {
		severityLevels := getSeverityLevelsAbove(minSeverity)
		filters := []string{}
		for _, sev := range severityLevels {
			filters = append(filters, fmt.Sprintf("CVE Severity:%s", sev))
		}
		query.Set("query", strings.Join(filters, "+"))
	}

	path := "/v1/nodes"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list nodes")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("list nodes failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	var response struct {
		Nodes []*NodeScan `json:"nodes"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errors.Wrap(err, "failed to parse nodes response")
	}

	// Limit CVEs per node if requested
	if maxCVEsPerNode > 0 {
		for _, node := range response.Nodes {
			if len(node.CVEs) > maxCVEsPerNode {
				node.CVEs = node.CVEs[:maxCVEsPerNode]
			}
		}
	}

	log.Info("Retrieved node vulnerabilities from Central", "count", len(response.Nodes))
	return response.Nodes, nil
}

// ConvertToCRD converts an ImageScan to ImageVulnerability CRD
func (img *ImageScan) ConvertToCRD() *securityv1alpha1.ImageVulnerability {
	vuln := &securityv1alpha1.ImageVulnerability{
		Spec: securityv1alpha1.ImageVulnerabilitySpec{},
	}

	// Image reference
	if img.Image != nil && img.Image.Name != nil {
		vuln.Spec.Image = securityv1alpha1.ImageReference{
			Name:     extractImageName(img.Image.Name.FullName),
			FullName: img.Image.Name.FullName,
			Registry: img.Image.Name.Registry,
			Remote:   img.Image.Name.Remote,
			Tag:      img.Image.Name.Tag,
		}

		if img.Image.Metadata != nil && img.Image.Metadata.V1 != nil {
			vuln.Spec.Image.SHA = img.Image.Metadata.V1.Digest
		}

		// Generate name from image
		vuln.Name = generateImageVulnName(img.Image.Name.FullName, vuln.Spec.Image.SHA)
	}

	// Scan time
	if timeVal, err := parseTime(img.ScanTime); err == nil {
		vuln.Spec.ScanTime = *timeVal
	}

	// Summary
	if img.Summary != nil {
		vuln.Spec.Summary = convertVulnSummary(img.Summary)
	}

	// CVEs
	if len(img.CVEs) > 0 {
		vuln.Spec.CVEs = make([]securityv1alpha1.CVE, len(img.CVEs))
		for i, cve := range img.CVEs {
			vuln.Spec.CVEs[i] = convertCVE(cve)
		}
	}

	// Labels
	vuln.Labels = map[string]string{
		"stackrox.io/image-name": sanitizeLabelValue(vuln.Spec.Image.Name),
	}

	if vuln.Spec.Image.Tag != "" {
		vuln.Labels["stackrox.io/image-tag"] = sanitizeLabelValue(vuln.Spec.Image.Tag)
	}

	if vuln.Spec.Image.Registry != "" {
		vuln.Labels["stackrox.io/registry"] = sanitizeLabelValue(vuln.Spec.Image.Registry)
	}

	// Add severity labels
	if vuln.Spec.Summary.Critical.Total > 0 {
		vuln.Labels["stackrox.io/has-critical"] = "true"
	}
	if vuln.Spec.Summary.FixableTotal > 0 {
		vuln.Labels["stackrox.io/has-fixable"] = "true"
	}

	return vuln
}

// ConvertToCRD converts a NodeScan to NodeVulnerability CRD
func (node *NodeScan) ConvertToCRD() *securityv1alpha1.NodeVulnerability {
	vuln := &securityv1alpha1.NodeVulnerability{
		Spec: securityv1alpha1.NodeVulnerabilitySpec{
			NodeName:      node.NodeName,
			OSImage:       node.OSImage,
			KernelVersion: node.KernelVersion,
		},
	}

	// Generate name from node name
	vuln.Name = generateNodeVulnName(node.NodeName)

	// Scan time
	if timeVal, err := parseTime(node.ScanTime); err == nil {
		vuln.Spec.ScanTime = *timeVal
	}

	// Summary
	if node.Summary != nil {
		vuln.Spec.Summary = convertVulnSummary(node.Summary)
	}

	// CVEs
	if len(node.CVEs) > 0 {
		vuln.Spec.CVEs = make([]securityv1alpha1.CVE, len(node.CVEs))
		for i, cve := range node.CVEs {
			vuln.Spec.CVEs[i] = convertCVE(cve)
		}
	}

	// Labels
	vuln.Labels = map[string]string{
		"stackrox.io/node-name": sanitizeLabelValue(node.NodeName),
	}

	if vuln.Spec.Summary.Critical.Total > 0 {
		vuln.Labels["stackrox.io/has-critical"] = "true"
	}

	return vuln
}

// Helper functions

func convertVulnSummary(summary *VulnSummary) securityv1alpha1.VulnerabilitySummary {
	result := securityv1alpha1.VulnerabilitySummary{
		Total:        summary.TotalCVEs,
		FixableTotal: summary.FixableCVEs,
	}

	if summary.CriticalSeverity != nil {
		result.Critical = &securityv1alpha1.SeverityCount{
			Total:   summary.CriticalSeverity.Total,
			Fixable: summary.CriticalSeverity.Fixable,
		}
	}

	if summary.HighSeverity != nil {
		result.High = &securityv1alpha1.SeverityCount{
			Total:   summary.HighSeverity.Total,
			Fixable: summary.HighSeverity.Fixable,
		}
	}

	if summary.MediumSeverity != nil {
		result.Medium = &securityv1alpha1.SeverityCount{
			Total:   summary.MediumSeverity.Total,
			Fixable: summary.MediumSeverity.Fixable,
		}
	}

	if summary.LowSeverity != nil {
		result.Low = &securityv1alpha1.SeverityCount{
			Total:   summary.LowSeverity.Total,
			Fixable: summary.LowSeverity.Fixable,
		}
	}

	return result
}

func convertCVE(cve *CVE) securityv1alpha1.CVE {
	result := securityv1alpha1.CVE{
		CVE:      cve.CVE,
		Severity: cve.Severity,
		Summary:  cve.Summary,
		Link:     cve.Link,
		CVSS:     cve.CVSS,
		Fixable:  cve.Fixable,
		FixedBy:  cve.FixedBy,
		State:    cve.State,
	}

	if cve.CVSSv3 != nil {
		result.CVSSv3 = &securityv1alpha1.CVSSv3{
			Score:  cve.CVSSv3.Score,
			Vector: cve.CVSSv3.Vector,
		}
	}

	if cve.Component != nil {
		result.Component = &securityv1alpha1.Component{
			Name:     cve.Component.Name,
			Version:  cve.Component.Version,
			Location: cve.Component.Location,
		}
	}

	if cve.EPSS != nil {
		result.EPSS = &securityv1alpha1.EPSS{
			Score:      cve.EPSS.Score,
			Percentile: cve.EPSS.Percentile,
		}
	}

	if cve.Published != "" {
		if timeVal, err := parseTime(cve.Published); err == nil {
			result.Published = timeVal
		}
	}

	if cve.DiscoveredInImage != "" {
		if timeVal, err := parseTime(cve.DiscoveredInImage); err == nil {
			result.DiscoveredInImage = timeVal
		}
	}

	return result
}

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

	// Clean up
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, ".", "-")

	tag = strings.ToLower(tag)
	tag = strings.ReplaceAll(tag, ".", "-")

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
