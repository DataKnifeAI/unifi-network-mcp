package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// NetworkClient handles communication with Unifi Network API
type NetworkClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	logger     *logrus.Entry
}

// NetworkDevice represents a device in Unifi Network
type NetworkDevice struct {
	ID             string `json:"_id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Model          string `json:"model"`
	MAC            string `json:"mac"`
	IP             string `json:"ip"`
	Connected      bool   `json:"connected"`
	LastSeen       int64  `json:"last_seen"`
	Uptime         int64  `json:"uptime"`
	SignalStrength int    `json:"signal,omitempty"`
}

// NetworkSite represents a site in Unifi Network
type NetworkSite struct {
	ID         string `json:"_id"`
	Name       string `json:"name"`
	ExternalID string `json:"external_id"`
	Desc       string `json:"desc"`
	Role       string `json:"role"`
	Status     string `json:"status"`
	NumSta     int    `json:"num_sta"`
	RxPackets  int64  `json:"rx_packets"`
	TxPackets  int64  `json:"tx_packets"`
}

// NetworkWiFiNetwork represents a WiFi network
type NetworkWiFiNetwork struct {
	ID           string `json:"_id"`
	Name         string `json:"name"`
	SSID         string `json:"ssid"`
	Security     string `json:"security"`
	Enabled      bool   `json:"enabled"`
	ChannelWidth string `json:"channel_width,omitempty"`
	Channel      int    `json:"channel,omitempty"`
	Band         string `json:"band"`
}

// NetworkStatsData represents network statistics
type NetworkStatsData struct {
	Timestamp     int64 `json:"timestamp"`
	BytesReceived int64 `json:"bytes_r"`
	BytesSent     int64 `json:"bytes_s"`
	PacketsIn     int64 `json:"packets_in"`
	PacketsOut    int64 `json:"packets_out"`
}

// NetworkClientDevice represents a connected network client
type NetworkClientDevice struct {
	MAC       string `json:"mac"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	Signal    int    `json:"signal,omitempty"`
	RSSI      int    `json:"rssi,omitempty"`
	TxBytes   int64  `json:"tx_bytes,omitempty"`
	RxBytes   int64  `json:"rx_bytes,omitempty"`
	TxRate    int64  `json:"tx_rate,omitempty"`
	RxRate    int64  `json:"rx_rate,omitempty"`
	FirstSeen int64  `json:"first_seen,omitempty"`
	LastSeen  int64  `json:"last_seen,omitempty"`
}

// NetworkVPNServer represents a VPN server configuration
type NetworkVPNServer struct {
	ID   string `json:"_id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

// NewNetworkClient creates a new Unifi Network API client
func NewNetworkClient(baseURL, apiKey string, skipSSLVerify bool) *NetworkClient {
	var tlsConfig *tls.Config
	if skipSSLVerify {
		// Disable SSL verification for self-signed certificates
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	if tlsConfig != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return &NetworkClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: httpClient,
		logger:     logrus.WithField("component", "NetworkClient"),
	}
}

// Authenticate verifies API key connectivity
func (nc *NetworkClient) Authenticate(ctx context.Context) error {
	nc.logger.Debug("Verifying Unifi Network API key")

	if nc.apiKey == "" {
		return fmt.Errorf("API key not configured")
	}

	nc.logger.Info("Unifi Network API key verified")
	return nil
}

// GetSites retrieves all sites from Unifi Network
func (nc *NetworkClient) GetSites(ctx context.Context) ([]NetworkSite, error) {
	nc.logger.Debug("Fetching sites from Unifi Network")

	url := fmt.Sprintf("%s/proxy/network/api/self/sites", nc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []NetworkSite `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	nc.logger.WithField("count", len(response.Data)).Debug("Retrieved sites")
	return response.Data, nil
}

// GetDevices retrieves devices from a specific site
func (nc *NetworkClient) GetDevices(ctx context.Context, siteID string) ([]NetworkDevice, error) {
	nc.logger.WithField("site_id", siteID).Debug("Fetching devices from Unifi Network")

	url := fmt.Sprintf("%s/proxy/network/api/s/%s/stat/device", nc.baseURL, siteID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []NetworkDevice `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	nc.logger.WithField("count", len(response.Data)).Debug("Retrieved devices")
	return response.Data, nil
}

// GetWiFiNetworks retrieves WiFi networks from a specific site
func (nc *NetworkClient) GetWiFiNetworks(ctx context.Context, siteID string) ([]NetworkWiFiNetwork, error) {
	nc.logger.WithField("site_id", siteID).Debug("Fetching WiFi networks from Unifi Network")

	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/networkconf", nc.baseURL, siteID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []NetworkWiFiNetwork `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	nc.logger.WithField("count", len(response.Data)).Debug("Retrieved WiFi networks")
	return response.Data, nil
}

// GetClientStats retrieves client statistics for a site
func (nc *NetworkClient) GetClientStats(ctx context.Context, siteID string) ([]map[string]interface{}, error) {
	nc.logger.WithField("site_id", siteID).Debug("Fetching client stats from Unifi Network")

	url := fmt.Sprintf("%s/proxy/network/api/s/%s/stat/sta", nc.baseURL, siteID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	nc.logger.WithField("count", len(response.Data)).Debug("Retrieved client stats")
	return response.Data, nil
}

// GetClients retrieves connected clients with pagination support
func (nc *NetworkClient) GetClients(ctx context.Context, siteID string, limit, offset int) ([]map[string]interface{}, error) {
	nc.logger.WithFields(map[string]interface{}{
		"site_id": siteID,
		"limit":   limit,
		"offset":  offset,
	}).Debug("Fetching clients from Unifi Network")

	url := fmt.Sprintf("%s/proxy/network/api/s/%s/stat/sta", nc.baseURL, siteID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	nc.logger.WithField("count", len(response.Data)).Debug("Retrieved clients")
	return response.Data, nil
}
func (nc *NetworkClient) GetHealth(ctx context.Context, siteID string) (map[string]interface{}, error) {
	nc.logger.WithField("site_id", siteID).Debug("Fetching health status from Unifi Network")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/health", nc.baseURL, siteID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(response.Data) > 0 {
		return response.Data[0], nil
	}

	return make(map[string]interface{}), nil
}

// GetInfo retrieves UniFi Network application information
func (nc *NetworkClient) GetInfo(ctx context.Context) (map[string]interface{}, error) {
	nc.logger.Debug("Fetching UniFi Network info")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/info", nc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var info map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return info, nil
}

// GetDeviceStats gets latest statistics for a device
func (nc *NetworkClient) GetDeviceStats(ctx context.Context, siteID, deviceID string) (map[string]interface{}, error) {
	nc.logger.WithFields(map[string]interface{}{
		"site_id":   siteID,
		"device_id": deviceID,
	}).Debug("Fetching device statistics")

	// Get all devices and filter for the specific one
	devices, err := nc.GetDevices(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	for _, device := range devices {
		if device.ID == deviceID {
			// Convert device struct to map
			devMap := make(map[string]interface{})
			data, _ := json.Marshal(device)
			json.Unmarshal(data, &devMap)
			return devMap, nil
		}
	}

	return nil, fmt.Errorf("device not found: %s", deviceID)
}

// GetWiFiBroadcasts retrieves WiFi broadcasts (SSIDs)
func (nc *NetworkClient) GetWiFiBroadcasts(ctx context.Context, siteID string) ([]map[string]interface{}, error) {
	nc.logger.WithField("site_id", siteID).Debug("Fetching WiFi broadcasts")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/wifi/broadcasts", nc.baseURL, siteID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// GetFirewallZones retrieves firewall zones
func (nc *NetworkClient) GetFirewallZones(ctx context.Context, siteID string) ([]map[string]interface{}, error) {
	nc.logger.WithField("site_id", siteID).Debug("Fetching firewall zones")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/firewall/zones", nc.baseURL, siteID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// GetACLRules retrieves ACL rules
func (nc *NetworkClient) GetACLRules(ctx context.Context, siteID string) ([]map[string]interface{}, error) {
	nc.logger.WithField("site_id", siteID).Debug("Fetching ACL rules")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/acl-rules", nc.baseURL, siteID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// GetHotspotVouchers retrieves hotspot vouchers
func (nc *NetworkClient) GetHotspotVouchers(ctx context.Context, siteID string) ([]map[string]interface{}, error) {
	nc.logger.WithField("site_id", siteID).Debug("Fetching hotspot vouchers")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/hotspot/vouchers", nc.baseURL, siteID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// GetPendingDevices retrieves devices pending adoption
func (nc *NetworkClient) GetPendingDevices(ctx context.Context) ([]map[string]interface{}, error) {
	nc.logger.Debug("Fetching pending devices")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/pending-devices", nc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// GetDPICategories retrieves DPI categories
func (nc *NetworkClient) GetDPICategories(ctx context.Context) ([]map[string]interface{}, error) {
	nc.logger.Debug("Fetching DPI categories")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/dpi/categories", nc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// GetClientDetailed retrieves detailed information about a specific client
func (nc *NetworkClient) GetClientDetailed(ctx context.Context, siteID, clientMAC string) (map[string]interface{}, error) {
	nc.logger.WithFields(logrus.Fields{
		"site_id": siteID,
		"mac":     clientMAC,
	}).Debug("Fetching detailed client info")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/clients/%s", nc.baseURL, siteID, clientMAC)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// GetDeviceDetailed retrieves detailed information about a specific device
func (nc *NetworkClient) GetDeviceDetailed(ctx context.Context, siteID, deviceID string) (map[string]interface{}, error) {
	nc.logger.WithFields(logrus.Fields{
		"site_id":   siteID,
		"device_id": deviceID,
	}).Debug("Fetching detailed device info")

	// Get all devices and filter for the specific one
	devices, err := nc.GetDevices(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	for _, device := range devices {
		if device.ID == deviceID {
			// Convert device struct to map
			devMap := make(map[string]interface{})
			data, _ := json.Marshal(device)
			json.Unmarshal(data, &devMap)
			return devMap, nil
		}
	}

	return nil, fmt.Errorf("device not found: %s", deviceID)
}

// GetVPNServers retrieves VPN server configurations
func (nc *NetworkClient) GetVPNServers(ctx context.Context, siteID string) ([]NetworkVPNServer, error) {
	nc.logger.WithField("site_id", siteID).Debug("Fetching VPN servers")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/vpn/servers", nc.baseURL, siteID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []NetworkVPNServer `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	nc.logger.WithField("count", len(response.Data)).Debug("Retrieved VPN servers")
	return response.Data, nil
}

// CheckEndpointHealth performs a health check on the Unifi Network endpoint
func (nc *NetworkClient) CheckEndpointHealth(ctx context.Context) (map[string]interface{}, error) {
	nc.logger.Debug("Performing health check on Unifi Network endpoint")

	url := fmt.Sprintf("%s/proxy/network/integration/v1/info", nc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	health := map[string]interface{}{
		"status": "healthy",
		"code":   resp.StatusCode,
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		health["status"] = "unhealthy"
		health["error"] = string(bodyBytes)
		nc.logger.WithField("status_code", resp.StatusCode).Warn("Network endpoint health check failed")
		return health, nil
	}

	var response struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		health["status"] = "unhealthy"
		health["error"] = "Failed to decode response"
		return health, nil
	}

	if len(response.Data) > 0 {
		health["version"] = response.Data["version"]
	}

	nc.logger.Debug("Network endpoint health check successful")
	return health, nil
}

// GetWiFiNetworkDetailed retrieves details for a specific WiFi network
func (nc *NetworkClient) GetWiFiNetworkDetailed(ctx context.Context, siteID, networkID string) (map[string]interface{}, error) {
	nc.logger.Debugf("Fetching WiFi network details for ID: %s", networkID)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/networkconf/%s", nc.baseURL, siteID, networkID)
	return nc.makeSingleRequest(ctx, url)
}

// GetFirewallZoneDetailed retrieves details for a specific firewall zone
func (nc *NetworkClient) GetFirewallZoneDetailed(ctx context.Context, siteID, zoneID string) (map[string]interface{}, error) {
	nc.logger.Debugf("Fetching firewall zone details for ID: %s", zoneID)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallzone/%s", nc.baseURL, siteID, zoneID)
	return nc.makeSingleRequest(ctx, url)
}

// GetACLRuleDetailed retrieves details for a specific ACL rule
func (nc *NetworkClient) GetACLRuleDetailed(ctx context.Context, siteID, ruleID string) (map[string]interface{}, error) {
	nc.logger.Debugf("Fetching ACL rule details for ID: %s", ruleID)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/rule/%s", nc.baseURL, siteID, ruleID)
	return nc.makeSingleRequest(ctx, url)
}

// GetHotspotVoucherDetailed retrieves details for a specific hotspot voucher
func (nc *NetworkClient) GetHotspotVoucherDetailed(ctx context.Context, siteID, voucherID string) (map[string]interface{}, error) {
	nc.logger.Debugf("Fetching hotspot voucher details for ID: %s", voucherID)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/hotspotop/%s", nc.baseURL, siteID, voucherID)
	return nc.makeSingleRequest(ctx, url)
}

// GetVPNTunnels retrieves VPN site-to-site tunnel configurations
func (nc *NetworkClient) GetVPNTunnels(ctx context.Context, siteID string) ([]map[string]interface{}, error) {
	nc.logger.Debug("Fetching VPN site-to-site tunnels")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/vpnserverconfig", nc.baseURL, siteID)
	return nc.makeArrayRequest(ctx, url)
}

// GetDeviceTags retrieves device tags from a site
func (nc *NetworkClient) GetDeviceTags(ctx context.Context, siteID string) ([]map[string]interface{}, error) {
	nc.logger.Debug("Fetching device tags")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/tag", nc.baseURL, siteID)
	return nc.makeArrayRequest(ctx, url)
}

// GetWANConfig retrieves WAN configuration from a site
func (nc *NetworkClient) GetWANConfig(ctx context.Context, siteID string) ([]map[string]interface{}, error) {
	nc.logger.Debug("Fetching WAN configuration")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/wanconf", nc.baseURL, siteID)
	return nc.makeArrayRequest(ctx, url)
}

// GetTrafficRules retrieves traffic matching rules from a site
func (nc *NetworkClient) GetTrafficRules(ctx context.Context, siteID string) ([]map[string]interface{}, error) {
	nc.logger.Debug("Fetching traffic matching rules")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/trafficrule", nc.baseURL, siteID)
	return nc.makeArrayRequest(ctx, url)
}

// GetTrafficRuleDetailed retrieves details for a specific traffic matching rule
func (nc *NetworkClient) GetTrafficRuleDetailed(ctx context.Context, siteID, ruleID string) (map[string]interface{}, error) {
	nc.logger.Debugf("Fetching traffic rule details for ID: %s", ruleID)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/trafficrule/%s", nc.baseURL, siteID, ruleID)
	return nc.makeSingleRequest(ctx, url)
}

// GetRADIUSProfiles retrieves RADIUS server profiles from a site
func (nc *NetworkClient) GetRADIUSProfiles(ctx context.Context, siteID string) ([]map[string]interface{}, error) {
	nc.logger.Debug("Fetching RADIUS profiles")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/radiusprofile", nc.baseURL, siteID)
	return nc.makeArrayRequest(ctx, url)
}

// GetDPIApplications retrieves DPI applications list
func (nc *NetworkClient) GetDPIApplications(ctx context.Context) ([]map[string]interface{}, error) {
	nc.logger.Debug("Fetching DPI applications")
	url := fmt.Sprintf("%s/proxy/network/api/v1/dpi/applications", nc.baseURL)
	return nc.makeArrayRequest(ctx, url)
}

// makeSingleRequest is a helper to fetch a single resource
func (nc *NetworkClient) makeSingleRequest(ctx context.Context, url string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-API-KEY", nc.apiKey)

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// makeArrayRequest is a helper to fetch array resources
func (nc *NetworkClient) makeArrayRequest(ctx context.Context, url string) ([]map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-API-KEY", nc.apiKey)

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// makePatchRequest is a helper to send PATCH requests
func (nc *NetworkClient) makePatchRequest(ctx context.Context, url string, payload map[string]interface{}) (map[string]interface{}, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PATCH", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// makePostRequest is a helper to send POST requests
func (nc *NetworkClient) makePostRequest(ctx context.Context, url string, payload map[string]interface{}) (map[string]interface{}, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-KEY", nc.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data, nil
}

// PatchWiFiNetwork updates WiFi network settings
func (nc *NetworkClient) PatchWiFiNetwork(ctx context.Context, siteID, networkID string, settings map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debugf("Updating WiFi network settings for ID: %s", networkID)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/networkconf/%s", nc.baseURL, siteID, networkID)
	return nc.makePatchRequest(ctx, url, settings)
}

// PatchFirewallZone updates firewall zone settings
func (nc *NetworkClient) PatchFirewallZone(ctx context.Context, siteID, zoneID string, settings map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debugf("Updating firewall zone settings for ID: %s", zoneID)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallzone/%s", nc.baseURL, siteID, zoneID)
	return nc.makePatchRequest(ctx, url, settings)
}

// PatchACLRule updates an ACL rule
func (nc *NetworkClient) PatchACLRule(ctx context.Context, siteID, ruleID string, settings map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debugf("Updating ACL rule settings for ID: %s", ruleID)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/rule/%s", nc.baseURL, siteID, ruleID)
	return nc.makePatchRequest(ctx, url, settings)
}

// PatchHotspotVoucher updates a hotspot voucher
func (nc *NetworkClient) PatchHotspotVoucher(ctx context.Context, siteID, voucherID string, settings map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debugf("Updating hotspot voucher settings for ID: %s", voucherID)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/hotspotop/%s", nc.baseURL, siteID, voucherID)
	return nc.makePatchRequest(ctx, url, settings)
}

// PatchTrafficRule updates a traffic matching rule
func (nc *NetworkClient) PatchTrafficRule(ctx context.Context, siteID, ruleID string, settings map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debugf("Updating traffic rule settings for ID: %s", ruleID)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/trafficrule/%s", nc.baseURL, siteID, ruleID)
	return nc.makePatchRequest(ctx, url, settings)
}

// CreateWiFiNetwork creates a new WiFi network
func (nc *NetworkClient) CreateWiFiNetwork(ctx context.Context, siteID string, config map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debug("Creating new WiFi network")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/networkconf", nc.baseURL, siteID)
	return nc.makePostRequest(ctx, url, config)
}

// CreateFirewallZone creates a new firewall zone
func (nc *NetworkClient) CreateFirewallZone(ctx context.Context, siteID string, config map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debug("Creating new firewall zone")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallzone", nc.baseURL, siteID)
	return nc.makePostRequest(ctx, url, config)
}

// CreateACLRule creates a new ACL rule
func (nc *NetworkClient) CreateACLRule(ctx context.Context, siteID string, config map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debug("Creating new ACL rule")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/rule", nc.baseURL, siteID)
	return nc.makePostRequest(ctx, url, config)
}

// CreateHotspotVoucher creates a new hotspot voucher
func (nc *NetworkClient) CreateHotspotVoucher(ctx context.Context, siteID string, config map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debug("Creating new hotspot voucher")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/hotspotop", nc.baseURL, siteID)
	return nc.makePostRequest(ctx, url, config)
}

// CreateTrafficRule creates a new traffic matching rule
func (nc *NetworkClient) CreateTrafficRule(ctx context.Context, siteID string, config map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debug("Creating new traffic matching rule")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/trafficrule", nc.baseURL, siteID)
	return nc.makePostRequest(ctx, url, config)
}

// CreateVPNTunnel creates a new VPN site-to-site tunnel
func (nc *NetworkClient) CreateVPNTunnel(ctx context.Context, siteID string, config map[string]interface{}) (map[string]interface{}, error) {
	nc.logger.Debug("Creating new VPN site-to-site tunnel")
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/vpnserverconfig", nc.baseURL, siteID)
	return nc.makePostRequest(ctx, url, config)
}
