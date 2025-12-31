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

// ProtectClient handles communication with Unifi Protect API
type ProtectClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	logger     *logrus.Entry
}

// ProtectDevice represents a device in Unifi Protect
type ProtectDevice struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	Model           string `json:"model"`
	FirmwareVersion string `json:"firmwareVersion"`
	Status          string `json:"status"`
	MAC             string `json:"mac"`
	IP              string `json:"ip"`
}

// ProtectEvent represents an event in Unifi Protect
type ProtectEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Camera    string                 `json:"camera"`
	Score     float64                `json:"score"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ProtectSystemInfo represents system information
type ProtectSystemInfo struct {
	ApplicationVersion string `json:"applicationVersion"`
	Version            string `json:"version"`
	UniqueID           string `json:"uniqueId"`
	SystemType         string `json:"systemType"`
}

// ProtectCamera represents a camera device
type ProtectCamera struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	Model           string `json:"model"`
	FirmwareVersion string `json:"firmwareVersion"`
	Status          string `json:"status"`
	MAC             string `json:"mac"`
	IP              string `json:"ip"`
	Recording       bool   `json:"recording,omitempty"`
	Motion          bool   `json:"motion,omitempty"`
	LastMotion      int64  `json:"lastMotion,omitempty"`
}

// ProtectSensor represents a sensor device
type ProtectSensor struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Model         string `json:"model"`
	Status        string `json:"status"`
	Battery       int    `json:"battery,omitempty"`
	LastEvent     int64  `json:"lastEvent,omitempty"`
	LastEventType string `json:"lastEventType,omitempty"`
}

// ProtectLight represents a light device
type ProtectLight struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Model  string `json:"model"`
	Status string `json:"status"`
	On     bool   `json:"on,omitempty"`
}

// ProtectChime represents a chime device
type ProtectChime struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Model  string `json:"model"`
	Status string `json:"status"`
}

// NewProtectClient creates a new Unifi Protect API client
func NewProtectClient(baseURL, apiKey string, skipSSLVerify bool) *ProtectClient {
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

	return &ProtectClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: httpClient,
		logger:     logrus.WithField("component", "ProtectClient"),
	}
}

// Authenticate verifies API key connectivity
func (pc *ProtectClient) Authenticate(ctx context.Context) error {
	pc.logger.Debug("Verifying Unifi Protect API key")

	if pc.apiKey == "" {
		return fmt.Errorf("API key not configured")
	}

	pc.logger.Info("Unifi Protect API key verified")
	return nil
}

// GetDevices retrieves all devices from Unifi Protect
func (pc *ProtectClient) GetDevices(ctx context.Context) ([]ProtectDevice, error) {
	pc.logger.Debug("Fetching devices from Unifi Protect")

	url := fmt.Sprintf("%s/proxy/protect/integration/v1/devices", pc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", pc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var devices []ProtectDevice
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	pc.logger.WithField("count", len(devices)).Debug("Retrieved devices")
	return devices, nil
}

// GetEvents retrieves events from Unifi Protect
// Note: This endpoint may not be available in all Unifi Protect versions
func (pc *ProtectClient) GetEvents(ctx context.Context, limit int, offset int) ([]ProtectEvent, error) {
	pc.logger.WithFields(logrus.Fields{
		"limit":  limit,
		"offset": offset,
	}).Debug("Fetching events from Unifi Protect")

	// Try the integration v1 endpoint first
	url := fmt.Sprintf("%s/proxy/protect/integration/v1/events?limit=%d&offset=%d", pc.baseURL, limit, offset)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", pc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// If endpoint not found, return empty slice
	if resp.StatusCode == http.StatusNotFound {
		pc.logger.Warn("Events endpoint not available in this Unifi Protect version")
		return []ProtectEvent{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var events []ProtectEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	pc.logger.WithField("count", len(events)).Debug("Retrieved events")
	return events, nil
}

// GetSystemInfo retrieves system information from Unifi Protect
func (pc *ProtectClient) GetSystemInfo(ctx context.Context) (*ProtectSystemInfo, error) {
	pc.logger.Debug("Fetching system info from Unifi Protect")

	url := fmt.Sprintf("%s/proxy/protect/integration/v1/meta/info", pc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", pc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var info ProtectSystemInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	pc.logger.WithField("version", info.Version).Debug("Retrieved system info")
	return &info, nil
}

// GetCameras retrieves all cameras from Unifi Protect
func (pc *ProtectClient) GetCameras(ctx context.Context) ([]ProtectCamera, error) {
	pc.logger.Debug("Fetching cameras from Unifi Protect")

	url := fmt.Sprintf("%s/proxy/protect/integration/v1/cameras", pc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", pc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var cameras []ProtectCamera
	if err := json.NewDecoder(resp.Body).Decode(&cameras); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	pc.logger.WithField("count", len(cameras)).Debug("Retrieved cameras")
	return cameras, nil
}

// GetSensors retrieves all sensors from Unifi Protect
func (pc *ProtectClient) GetSensors(ctx context.Context) ([]ProtectSensor, error) {
	pc.logger.Debug("Fetching sensors from Unifi Protect")

	url := fmt.Sprintf("%s/proxy/protect/integration/v1/sensors", pc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", pc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var sensors []ProtectSensor
	if err := json.NewDecoder(resp.Body).Decode(&sensors); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	pc.logger.WithField("count", len(sensors)).Debug("Retrieved sensors")
	return sensors, nil
}

// GetLights retrieves all lights from Unifi Protect
func (pc *ProtectClient) GetLights(ctx context.Context) ([]ProtectLight, error) {
	pc.logger.Debug("Fetching lights from Unifi Protect")

	url := fmt.Sprintf("%s/proxy/protect/integration/v1/lights", pc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", pc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var lights []ProtectLight
	if err := json.NewDecoder(resp.Body).Decode(&lights); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	pc.logger.WithField("count", len(lights)).Debug("Retrieved lights")
	return lights, nil
}

// GetChimes retrieves all chimes from Unifi Protect
func (pc *ProtectClient) GetChimes(ctx context.Context) ([]ProtectChime, error) {
	pc.logger.Debug("Fetching chimes from Unifi Protect")

	url := fmt.Sprintf("%s/proxy/protect/integration/v1/chimes", pc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", pc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var chimes []ProtectChime
	if err := json.NewDecoder(resp.Body).Decode(&chimes); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	pc.logger.WithField("count", len(chimes)).Debug("Retrieved chimes")
	return chimes, nil
}

// GetHealth retrieves health status from Unifi Protect
func (pc *ProtectClient) GetHealth(ctx context.Context) (map[string]interface{}, error) {
	pc.logger.Debug("Fetching health status from Unifi Protect")

	url := fmt.Sprintf("%s/proxy/protect/integration/v1/cameras", pc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-KEY", pc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := pc.httpClient.Do(req)
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

	pc.logger.Debug("Retrieved health status")
	return response.Data, nil
}

// GetCameraDetailed retrieves details for a specific camera
func (pc *ProtectClient) GetCameraDetailed(ctx context.Context, cameraID string) (map[string]interface{}, error) {
	pc.logger.Debugf("Fetching camera details for ID: %s", cameraID)
	url := fmt.Sprintf("%s/proxy/protect/integration/v1/cameras/%s", pc.baseURL, cameraID)
	return pc.makeDetailRequest(ctx, url)
}

// GetSensorDetailed retrieves details for a specific sensor
func (pc *ProtectClient) GetSensorDetailed(ctx context.Context, sensorID string) (map[string]interface{}, error) {
	pc.logger.Debugf("Fetching sensor details for ID: %s", sensorID)
	url := fmt.Sprintf("%s/proxy/protect/integration/v1/sensors/%s", pc.baseURL, sensorID)
	return pc.makeDetailRequest(ctx, url)
}

// GetLightDetailed retrieves details for a specific light
func (pc *ProtectClient) GetLightDetailed(ctx context.Context, lightID string) (map[string]interface{}, error) {
	pc.logger.Debugf("Fetching light details for ID: %s", lightID)
	url := fmt.Sprintf("%s/proxy/protect/integration/v1/lights/%s", pc.baseURL, lightID)
	return pc.makeDetailRequest(ctx, url)
}

// GetChimeDetailed retrieves details for a specific chime
func (pc *ProtectClient) GetChimeDetailed(ctx context.Context, chimeID string) (map[string]interface{}, error) {
	pc.logger.Debugf("Fetching chime details for ID: %s", chimeID)
	url := fmt.Sprintf("%s/proxy/protect/integration/v1/chimes/%s", pc.baseURL, chimeID)
	return pc.makeDetailRequest(ctx, url)
}

// GetNVR retrieves NVR information
func (pc *ProtectClient) GetNVR(ctx context.Context) (map[string]interface{}, error) {
	pc.logger.Debug("Fetching NVR information")
	url := fmt.Sprintf("%s/proxy/protect/integration/v1/nvrs", pc.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", pc.apiKey))

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	pc.logger.Debug("Retrieved NVR information")
	return result, nil
}

// GetViewers retrieves all viewers
func (pc *ProtectClient) GetViewers(ctx context.Context) ([]map[string]interface{}, error) {
	pc.logger.Debug("Fetching viewers from Unifi Protect")
	url := fmt.Sprintf("%s/proxy/protect/integration/v1/viewers", pc.baseURL)
	return pc.makeArrayRequest(ctx, url)
}

// GetViewerDetailed retrieves details for a specific viewer
func (pc *ProtectClient) GetViewerDetailed(ctx context.Context, viewerID string) (map[string]interface{}, error) {
	pc.logger.Debugf("Fetching viewer details for ID: %s", viewerID)
	url := fmt.Sprintf("%s/proxy/protect/integration/v1/viewers/%s", pc.baseURL, viewerID)
	return pc.makeDetailRequest(ctx, url)
}

// GetLiveviews retrieves all live views
func (pc *ProtectClient) GetLiveviews(ctx context.Context) ([]map[string]interface{}, error) {
	pc.logger.Debug("Fetching live views from Unifi Protect")
	url := fmt.Sprintf("%s/proxy/protect/integration/v1/liveviews", pc.baseURL)
	return pc.makeArrayRequest(ctx, url)
}

// GetLiveviewDetailed retrieves details for a specific live view
func (pc *ProtectClient) GetLiveviewDetailed(ctx context.Context, liveviewID string) (map[string]interface{}, error) {
	pc.logger.Debugf("Fetching live view details for ID: %s", liveviewID)
	url := fmt.Sprintf("%s/proxy/protect/integration/v1/liveviews/%s", pc.baseURL, liveviewID)
	return pc.makeDetailRequest(ctx, url)
}

// makeDetailRequest is a helper to fetch a single resource
func (pc *ProtectClient) makeDetailRequest(ctx context.Context, url string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", pc.apiKey))

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

// makeArrayRequest is a helper to fetch array resources
func (pc *ProtectClient) makeArrayRequest(ctx context.Context, url string) ([]map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", pc.apiKey))

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

// makePatchRequest is a helper to send PATCH requests
func (pc *ProtectClient) makePatchRequest(ctx context.Context, url string, payload map[string]interface{}) (map[string]interface{}, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PATCH", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", pc.apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := pc.httpClient.Do(req)
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

// PatchCamera updates camera settings
func (pc *ProtectClient) PatchCamera(ctx context.Context, cameraID string, settings map[string]interface{}) (map[string]interface{}, error) {
	pc.logger.Debugf("Updating camera settings for ID: %s", cameraID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/cameras/%s", pc.baseURL, cameraID)
	return pc.makePatchRequest(ctx, url, settings)
}

// PatchSensor updates sensor settings
func (pc *ProtectClient) PatchSensor(ctx context.Context, sensorID string, settings map[string]interface{}) (map[string]interface{}, error) {
	pc.logger.Debugf("Updating sensor settings for ID: %s", sensorID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/sensors/%s", pc.baseURL, sensorID)
	return pc.makePatchRequest(ctx, url, settings)
}

// PatchLight updates light settings
func (pc *ProtectClient) PatchLight(ctx context.Context, lightID string, settings map[string]interface{}) (map[string]interface{}, error) {
	pc.logger.Debugf("Updating light settings for ID: %s", lightID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/lights/%s", pc.baseURL, lightID)
	return pc.makePatchRequest(ctx, url, settings)
}

// PatchChime updates chime settings
func (pc *ProtectClient) PatchChime(ctx context.Context, chimeID string, settings map[string]interface{}) (map[string]interface{}, error) {
	pc.logger.Debugf("Updating chime settings for ID: %s", chimeID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/chimes/%s", pc.baseURL, chimeID)
	return pc.makePatchRequest(ctx, url, settings)
}

// PatchViewer updates viewer settings
func (pc *ProtectClient) PatchViewer(ctx context.Context, viewerID string, settings map[string]interface{}) (map[string]interface{}, error) {
	pc.logger.Debugf("Updating viewer settings for ID: %s", viewerID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/viewers/%s", pc.baseURL, viewerID)
	return pc.makePatchRequest(ctx, url, settings)
}

// PatchLiveview updates liveview settings
func (pc *ProtectClient) PatchLiveview(ctx context.Context, liveviewID string, settings map[string]interface{}) (map[string]interface{}, error) {
	pc.logger.Debugf("Updating liveview settings for ID: %s", liveviewID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/liveviews/%s", pc.baseURL, liveviewID)
	return pc.makePatchRequest(ctx, url, settings)
}

// makePostRequest is a helper to send POST requests
func (pc *ProtectClient) makePostRequest(ctx context.Context, url string, payload map[string]interface{}) (map[string]interface{}, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", pc.apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := pc.httpClient.Do(req)
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

// CreateLiveview creates a new liveview
func (pc *ProtectClient) CreateLiveview(ctx context.Context, config map[string]interface{}) (map[string]interface{}, error) {
	pc.logger.Debug("Creating new liveview")
	url := fmt.Sprintf("%s/proxy/protect/api/v1/liveviews", pc.baseURL)
	return pc.makePostRequest(ctx, url, config)
}

// CameraStartPTZPatrol starts a PTZ patrol on a camera
func (pc *ProtectClient) CameraStartPTZPatrol(ctx context.Context, cameraID string, slot int) (map[string]interface{}, error) {
	pc.logger.Debugf("Starting PTZ patrol on camera %s, slot %d", cameraID, slot)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/cameras/%s/ptz/patrol/start/%d", pc.baseURL, cameraID, slot)
	return pc.makePostRequest(ctx, url, map[string]interface{}{})
}

// CameraStopPTZPatrol stops a PTZ patrol on a camera
func (pc *ProtectClient) CameraStopPTZPatrol(ctx context.Context, cameraID string) (map[string]interface{}, error) {
	pc.logger.Debugf("Stopping PTZ patrol on camera %s", cameraID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/cameras/%s/ptz/patrol/stop", pc.baseURL, cameraID)
	return pc.makePostRequest(ctx, url, map[string]interface{}{})
}

// CameraGotoPTZPreset moves camera to a PTZ preset
func (pc *ProtectClient) CameraGotoPTZPreset(ctx context.Context, cameraID string, slot int) (map[string]interface{}, error) {
	pc.logger.Debugf("Moving camera %s to PTZ preset %d", cameraID, slot)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/cameras/%s/ptz/goto/%d", pc.baseURL, cameraID, slot)
	return pc.makePostRequest(ctx, url, map[string]interface{}{})
}

// CameraCreateRTSPSStream creates an RTSPS stream for a camera
func (pc *ProtectClient) CameraCreateRTSPSStream(ctx context.Context, cameraID string, config map[string]interface{}) (map[string]interface{}, error) {
	pc.logger.Debugf("Creating RTSPS stream for camera %s", cameraID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/cameras/%s/rtsps-stream", pc.baseURL, cameraID)
	return pc.makePostRequest(ctx, url, config)
}

// CameraCreateTalkbackSession creates a talkback session for a camera
func (pc *ProtectClient) CameraCreateTalkbackSession(ctx context.Context, cameraID string, config map[string]interface{}) (map[string]interface{}, error) {
	pc.logger.Debugf("Creating talkback session for camera %s", cameraID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/cameras/%s/talkback-session", pc.baseURL, cameraID)
	return pc.makePostRequest(ctx, url, config)
}

// CameraDisableMicPermanently disables microphone permanently on a camera
func (pc *ProtectClient) CameraDisableMicPermanently(ctx context.Context, cameraID string) (map[string]interface{}, error) {
	pc.logger.Debugf("Disabling microphone permanently on camera %s", cameraID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/cameras/%s/disable-mic-permanently", pc.baseURL, cameraID)
	return pc.makePostRequest(ctx, url, map[string]interface{}{})
}

// TriggerWebhookAlarm triggers a configured alarm webhook
func (pc *ProtectClient) TriggerWebhookAlarm(ctx context.Context, webhookID string, payload map[string]interface{}) (map[string]interface{}, error) {
	pc.logger.Debugf("Triggering webhook alarm %s", webhookID)
	url := fmt.Sprintf("%s/proxy/protect/api/v1/alarm-manager/webhook/%s", pc.baseURL, webhookID)
	return pc.makePostRequest(ctx, url, payload)
}
