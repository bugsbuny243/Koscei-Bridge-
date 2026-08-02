package retentionexport

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func LoadConfigFromEnv() Config {
	return Config{
		Sink:       envString("KOSCHEI_RADAR_ARCHIVE_EXPORT_SINK", "disabled"),
		BatchSize:  envInt("KOSCHEI_RADAR_ARCHIVE_EXPORT_BATCH_SIZE", 500, 1, 5000),
		MaxBatches: envInt("KOSCHEI_RADAR_ARCHIVE_EXPORT_MAX_BATCHES", 10, 1, 100),
		Prefix:     envString("KOSCHEI_RADAR_ARCHIVE_EXPORT_PREFIX", "radar-retention"),

		FilesystemPath: strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_ARCHIVE_EXPORT_FILESYSTEM_PATH")),

		S3Endpoint:        strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_ARCHIVE_EXPORT_S3_ENDPOINT")),
		S3Bucket:          strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_ARCHIVE_EXPORT_S3_BUCKET")),
		S3Region:          envString("KOSCHEI_RADAR_ARCHIVE_EXPORT_S3_REGION", "us-east-1"),
		S3AccessKeyID:     strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_ARCHIVE_EXPORT_S3_ACCESS_KEY_ID")),
		S3SecretAccessKey: strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_ARCHIVE_EXPORT_S3_SECRET_ACCESS_KEY")),
		S3SessionToken:    strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_ARCHIVE_EXPORT_S3_SESSION_TOKEN")),
		S3PathStyle:       envBool("KOSCHEI_RADAR_ARCHIVE_EXPORT_S3_PATH_STYLE", true),
	}
}

func NewSink(config Config) (Sink, error) {
	switch strings.ToLower(strings.TrimSpace(config.Sink)) {
	case "disabled", "":
		return nil, nil
	case "filesystem":
		return NewFilesystemSink(config.FilesystemPath)
	case "s3":
		return NewS3Sink(S3Config{
			Endpoint:        config.S3Endpoint,
			Bucket:          config.S3Bucket,
			Region:          config.S3Region,
			AccessKeyID:     config.S3AccessKeyID,
			SecretAccessKey: config.S3SecretAccessKey,
			SessionToken:    config.S3SessionToken,
			PathStyle:       config.S3PathStyle,
		})
	default:
		return nil, fmt.Errorf("unsupported retention export sink %q", config.Sink)
	}
}

func RunFromEnv(ctx context.Context, db *sql.DB) (Result, error) {
	config := LoadConfigFromEnv()
	if strings.EqualFold(strings.TrimSpace(config.Sink), "disabled") || strings.TrimSpace(config.Sink) == "" {
		return Result{Enabled: false}, nil
	}
	if db == nil {
		return Result{Enabled: true}, fmt.Errorf("retention export database is required")
	}
	sink, err := NewSink(config)
	if err != nil {
		return Result{Enabled: true, Sink: strings.TrimSpace(config.Sink)}, err
	}
	exporter := Exporter{
		Repository: NewSQLRepository(db),
		Sink:       sink,
		Config:     config,
	}
	return exporter.Run(ctx)
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback, minimum, maximum int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func envBool(name string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}
