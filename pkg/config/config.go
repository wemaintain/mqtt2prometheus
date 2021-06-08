package config

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
)

const (
	GaugeValueType   = "gauge"
	CounterValueType = "counter"

	DeviceIDRegexGroup   = "deviceid"
	MetricNameRegexGroup = "metricname"
)

var MQTTConfigDefaults = MQTTConfig{
	Server:        "tcp://127.0.0.1:1883",
	TopicPath:     "v1/devices/me",
	DeviceIDRegex: MustNewRegexp(fmt.Sprintf("(.*/)?(?P<%s>.*)", DeviceIDRegexGroup)),
	QoS:           0,
}

var CacheConfigDefaults = CacheConfig{
	Timeout: 2 * time.Minute,
}

type Regexp struct {
	r       *regexp.Regexp
	pattern string
}

func (rf *Regexp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var pattern string
	if err := unmarshal(&pattern); err != nil {
		return err
	}
	r, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	rf.r = r
	rf.pattern = pattern
	return nil
}

func (rf *Regexp) MarshalYAML() (interface{}, error) {
	if rf == nil {
		return "", nil
	}
	return rf.pattern, nil
}

func (rf *Regexp) Match(s string) bool {
	return rf == nil || rf.r == nil || rf.r.MatchString(s)
}

// GroupValue returns the value of the given group. If the group is not part of the underlying regexp, returns the empty string.
func (rf *Regexp) GroupValue(s string, groupName string) string {
	match := rf.r.FindStringSubmatch(s)
	groupValues := make(map[string]string)
	for i, name := range rf.r.SubexpNames() {
		if len(match) > i && name != "" {
			groupValues[name] = match[i]
		}
	}
	return groupValues[groupName]
}

func (rf *Regexp) RegEx() *regexp.Regexp {
	return rf.r
}

func MustNewRegexp(pattern string) *Regexp {
	return &Regexp{
		pattern: pattern,
		r:       regexp.MustCompile(pattern),
	}
}

type Config struct {
	Metrics []MetricConfig `yaml:"metrics"`
	MQTT    *MQTTConfig    `yaml:"mqtt,omitempty"`
	Cache   *CacheConfig   `yaml:"cache,omitempty"`
	AWS     *AWSConfig     `yaml:"aws,omitempty"`
}

type AWSConfig struct {
	Region   string `yaml:"region"`
	IotWsUrl string `yaml:"iot_ws_url"`
}

type CacheConfig struct {
	Timeout time.Duration `yaml:"timeout"`
}

type MQTTConfig struct {
	Server               string                `yaml:"server"`
	TopicPath            string                `yaml:"topic_path"`
	DeviceIDRegex        *Regexp               `yaml:"device_id_regex"`
	User                 string                `yaml:"user"`
	Password             string                `yaml:"password"`
	QoS                  byte                  `yaml:"qos"`
	ObjectPerTopicConfig *ObjectPerTopicConfig `yaml:"object_per_topic_config"`
	MetricPerTopicConfig *MetricPerTopicConfig `yaml:"metric_per_topic_config"`
	CACert               string                `yaml:"ca_cert"`
	ClientCert           string                `yaml:"client_cert"`
	ClientKey            string                `yaml:"client_key"`
	ClientID             string                `yaml:"client_id"`
}

const EncodingJSON = "JSON"

type ObjectPerTopicConfig struct {
	Encoding string `yaml:"encoding"` // Currently only JSON is a valid value
}

type MetricPerTopicConfig struct {
	MetricNameRegex *Regexp `yaml:"metric_name_regex"` // Default
}

// Metrics Config is a mapping between a metric send on mqtt to a prometheus metric
type MetricConfig struct {
	PrometheusName     string                    `yaml:"prom_name"`
	MQTTName           string                    `yaml:"mqtt_name"`
	SensorNameFilter   Regexp                    `yaml:"sensor_name_filter"`
	Help               string                    `yaml:"help"`
	ValueType          string                    `yaml:"type"`
	ConstantLabels     map[string]string         `yaml:"const_labels"`
	StringValueMapping *StringValueMappingConfig `yaml:"string_value_mapping"`
}

// StringValueMappingConfig defines the mapping from string to float
type StringValueMappingConfig struct {
	// ErrorValue is used when no mapping is found in Map
	ErrorValue *float64           `yaml:"error_value"`
	Map        map[string]float64 `yaml:"map"`
}

func (mc *MetricConfig) PrometheusDescription() *prometheus.Desc {
	return prometheus.NewDesc(
		mc.PrometheusName, mc.Help, []string{"sensor", "topic"}, mc.ConstantLabels,
	)
}

func (mc *MetricConfig) PrometheusValueType() prometheus.ValueType {
	switch mc.ValueType {
	case GaugeValueType:
		return prometheus.GaugeValue
	case CounterValueType:
		return prometheus.CounterValue
	default:
		return prometheus.UntypedValue
	}
}

// Forked from https://github.com/aws/aws-sdk-go/issues/820#issuecomment-660139762
func AwsIotWsUrl(p client.ConfigProvider, endpoint string) (string, error) {
	serviceName := "iotdevicegateway"
	config := p.ClientConfig(serviceName)
	region := *config.Config.Region
	creds, err := config.Config.Credentials.Get()
	if err != nil {
		return "", err
	}

	accessKey := creds.AccessKeyID
	secretKey := creds.SecretAccessKey
	sessionToken := creds.SessionToken

	// according to docs, time must be within 5min of actual time (or at least according to AWS servers)
	now := time.Now().UTC()

	dateLong := now.Format("20060102T150405Z")
	dateShort := dateLong[:8]
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", dateShort, region, serviceName)
	alg := "AWS4-HMAC-SHA256"
	q := [][2]string{
		{"X-Amz-Algorithm", alg},
		{"X-Amz-Credential", accessKey + "/" + scope},
		{"X-Amz-Date", dateLong},
		{"X-Amz-SignedHeaders", "host"},
	}
	query := awsQueryParams(q)

	signKey := awsSignKey(secretKey, dateShort, region, serviceName)
	stringToSign := awsSignString(accessKey, secretKey, query, endpoint, dateLong, alg, scope)
	signature := fmt.Sprintf("%x", awsHmac(signKey, []byte(stringToSign)))

	return fmt.Sprintf("wss://%s/mqtt?%s&X-Amz-Signature=%s&X-Amz-Security-Token=%s", endpoint, query, signature, url.QueryEscape(sessionToken)), nil
}

func awsQueryParams(q [][2]string) string {
	var buff bytes.Buffer
	var i int
	for _, param := range q {
		if i != 0 {
			buff.WriteRune('&')
		}
		i++
		buff.WriteString(param[0])
		buff.WriteRune('=')
		buff.WriteString(url.QueryEscape(param[1]))
	}
	return buff.String()
}

func awsSignString(accessKey string, secretKey string, query string, host string, dateLongStr string, alg string, scopeStr string) string {
	emptyStringHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	req := strings.Join([]string{
		"GET",
		"/mqtt",
		query,
		"host:" + host,
		"", // separator
		"host",
		emptyStringHash,
	}, "\n")
	return strings.Join([]string{
		alg,
		dateLongStr,
		scopeStr,
		awsSha(req),
	}, "\n")
}

func awsHmac(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func awsSignKey(secretKey string, dateShort string, region string, serviceName string) []byte {
	h := awsHmac([]byte("AWS4"+secretKey), []byte(dateShort))
	h = awsHmac(h, []byte(region))
	h = awsHmac(h, []byte(serviceName))
	h = awsHmac(h, []byte("aws4_request"))
	return h
}

func awsSha(in string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s", in)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func LoadConfig(configFile string) (Config, error) {
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err = yaml.UnmarshalStrict(configData, &cfg); err != nil {
		return cfg, err
	}
	if cfg.MQTT == nil {
		cfg.MQTT = &MQTTConfigDefaults
	}

	if cfg.AWS != nil {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(cfg.AWS.Region)},
		)
		addr, err := AwsIotWsUrl(sess, cfg.AWS.IotWsUrl)
		if err != nil {
			return Config{}, fmt.Errorf("no wss for aws iot generated: %v", err)
		}
		cfg.MQTT.Server = addr
	}

	if cfg.Cache == nil {
		cfg.Cache = &CacheConfigDefaults
	}
	if cfg.MQTT.DeviceIDRegex == nil {
		cfg.MQTT.DeviceIDRegex = MQTTConfigDefaults.DeviceIDRegex
	}
	var validRegex bool
	for _, name := range cfg.MQTT.DeviceIDRegex.RegEx().SubexpNames() {
		if name == DeviceIDRegexGroup {
			validRegex = true
		}
	}
	if !validRegex {
		return Config{}, fmt.Errorf("device id regex %q does not contain required regex group %q", cfg.MQTT.DeviceIDRegex.pattern, DeviceIDRegexGroup)
	}
	if cfg.MQTT.ObjectPerTopicConfig == nil && cfg.MQTT.MetricPerTopicConfig == nil {
		cfg.MQTT.ObjectPerTopicConfig = &ObjectPerTopicConfig{
			Encoding: EncodingJSON,
		}
	}

	if cfg.MQTT.MetricPerTopicConfig != nil {
		validRegex = false
		for _, name := range cfg.MQTT.MetricPerTopicConfig.MetricNameRegex.RegEx().SubexpNames() {
			if name == MetricNameRegexGroup {
				validRegex = true
			}
		}
		if !validRegex {
			return Config{}, fmt.Errorf("metric name regex %q does not contain required regex group %q", cfg.MQTT.DeviceIDRegex.pattern, MetricNameRegexGroup)
		}
	}

	return cfg, nil
}
