package snshttp

type BaseMessage struct {
	Type             string
	MessageID        string `json:"MessageId"`
	TopicARN         string `json:"TopicArn"`
	Message          string
	Timestamp        string
	SignatureVersion string
	Signature        string
	SigningCertURL   string
}

func (m *BaseMessage) getSignature() string {
	return m.Signature
}

func (m *BaseMessage) getSigningCertURL() string {
	return m.SigningCertURL
}

func (m *BaseMessage) getSignatureVersion() string {
	return m.SignatureVersion
}
