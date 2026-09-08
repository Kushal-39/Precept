package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/precept/precept/internal/models"
)

// CloudTrailParser parses AWS CloudTrail event logs (Records envelopes,
// bare single events, or arrays of events) into one resource per event.
// CloudTrail records carry arbitrary service-specific fields, so decoding
// is lenient: only the fields Precept consumes are extracted and records
// without eventName and eventSource are rejected.
type CloudTrailParser struct {
	maxBytes int64
}

// NewCloudTrailParser returns a CloudTrail parser with the given per-file
// size limit; zero or less selects MaxFileSize.
func NewCloudTrailParser(maxBytes int64) *CloudTrailParser {
	return &CloudTrailParser{maxBytes: maxBytes}
}

// SupportedExtensions returns the CloudTrail file extensions this parser accepts.
func (p *CloudTrailParser) SupportedExtensions() []string {
	return []string{".json"}
}

// Parse reads path and normalises every event record into a Resource.
func (p *CloudTrailParser) Parse(path string) ([]*models.Resource, error) {
	data, err := readFileLimited(path, p.maxBytes)
	if err != nil {
		return nil, err
	}
	return parseCloudTrailData(data, path)
}

type ctRecord struct {
	EventVersion      string         `json:"eventVersion"`
	EventID           string         `json:"eventID"`
	EventTime         string         `json:"eventTime"`
	EventName         string         `json:"eventName"`
	EventSource       string         `json:"eventSource"`
	AWSRegion         string         `json:"awsRegion"`
	SourceIPAddress   string         `json:"sourceIPAddress"`
	UserAgent         string         `json:"userAgent"`
	UserIdentity      map[string]any `json:"userIdentity"`
	RequestParameters map[string]any `json:"requestParameters"`
	ResponseElements  map[string]any `json:"responseElements"`
	ReadOnly          any            `json:"readOnly"`
	Resources         []any          `json:"resources"`
	ErrorCode         string         `json:"errorCode"`
	ErrorMessage      string         `json:"errorMessage"`
}

type ctEnvelope struct {
	Records json.RawMessage `json:"Records"`
}

func parseCloudTrailData(data []byte, path string) ([]*models.Resource, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	var records []ctRecord
	switch {
	case len(trimmed) > 0 && trimmed[0] == '[':
		if err := decodeJSONLenient(data, &records); err != nil {
			return nil, fmt.Errorf("invalid cloudtrail json: %w", err)
		}
	default:
		var env ctEnvelope
		if err := decodeJSONLenient(data, &env); err != nil {
			return nil, fmt.Errorf("invalid cloudtrail json: %w", err)
		}
		if env.Records != nil {
			if err := decodeJSONLenient(env.Records, &records); err != nil {
				return nil, fmt.Errorf("invalid cloudtrail json: %w", err)
			}
		} else {
			var single ctRecord
			if err := decodeJSONLenient(data, &single); err != nil {
				return nil, fmt.Errorf("invalid cloudtrail json: %w", err)
			}
			records = []ctRecord{single}
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: Records", ErrMissingField)
	}

	out := make([]*models.Resource, 0, len(records))
	for i := range records {
		rec := &records[i]
		if rec.EventName == "" {
			return nil, fmt.Errorf("%w: eventName (record %d)", ErrMissingField, i)
		}
		if rec.EventSource == "" {
			return nil, fmt.Errorf("%w: eventSource (record %d)", ErrMissingField, i)
		}
		id := rec.EventID
		if id == "" {
			id = fmt.Sprintf("%s/%s#%d", rec.EventSource, rec.EventName, i)
		}
		r, err := models.NewResource(id, rec.EventName, rec.EventName, string(models.ResourceTypeCloudTrail), cloudTrailProperties(rec))
		if err != nil {
			return nil, err
		}
		r.Metadata["file"] = path
		r.Metadata["record_index"] = strconv.Itoa(i)
		out = append(out, r)
	}
	return out, nil
}

func cloudTrailProperties(rec *ctRecord) map[string]any {
	props := map[string]any{
		"event_name":   rec.EventName,
		"event_source": rec.EventSource,
	}
	setStringIf := func(key, value string) {
		if value != "" {
			props[key] = value
		}
	}
	setStringIf("event_version", rec.EventVersion)
	setStringIf("event_id", rec.EventID)
	setStringIf("event_time", rec.EventTime)
	setStringIf("aws_region", rec.AWSRegion)
	setStringIf("source_ip_address", rec.SourceIPAddress)
	setStringIf("user_agent", rec.UserAgent)
	setStringIf("error_code", rec.ErrorCode)
	setStringIf("error_message", rec.ErrorMessage)
	if rec.UserIdentity != nil {
		props["user_identity"] = rec.UserIdentity
	}
	if rec.RequestParameters != nil {
		props["request_parameters"] = rec.RequestParameters
	}
	if rec.ResponseElements != nil {
		props["response_elements"] = rec.ResponseElements
	}
	if rec.ReadOnly != nil {
		props["read_only"] = rec.ReadOnly
	}
	if len(rec.Resources) > 0 {
		props["resources"] = rec.Resources
	}
	return props
}
