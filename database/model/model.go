package model

import (
	"fmt"
	"x-ui/util/json_util"
	"x-ui/xray"
)

type Protocol string

const (
	VMess       Protocol = "vmess"
	VLESS       Protocol = "vless"
	Dokodemo    Protocol = "Dokodemo-door"
	Http        Protocol = "http"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
)

type User struct {
	Id          int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	LoginSecret string `json:"loginSecret"`
}

type Inbound struct {
	Id          int                  `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	UserId      int                  `json:"-"`
	Up          int64                `json:"up" form:"up"`
	Down        int64                `json:"down" form:"down"`
	Total       int64                `json:"total" form:"total"`
	Remark      string               `json:"remark" form:"remark"`
	Enable      bool                 `json:"enable" form:"enable"`
	ExpiryTime  int64                `json:"expiryTime" form:"expiryTime"`
	ClientStats []xray.ClientTraffic `gorm:"foreignKey:InboundId;references:Id" json:"clientStats" form:"clientStats"`

	// config part
	Listen         string   `json:"listen" form:"listen"`
	Port           int      `json:"port" form:"port"`
	Protocol       Protocol `json:"protocol" form:"protocol"`
	Settings       string   `json:"settings" form:"settings"`
	StreamSettings string   `json:"streamSettings" form:"streamSettings"`
	Tag            string   `json:"tag" form:"tag" gorm:"unique"`
	Sniffing       string   `json:"sniffing" form:"sniffing"`
}

type OutboundTraffics struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Tag   string `json:"tag" form:"tag" gorm:"unique"`
	Up    int64  `json:"up" form:"up" gorm:"default:0"`
	Down  int64  `json:"down" form:"down" gorm:"default:0"`
	Total int64  `json:"total" form:"total" gorm:"default:0"`
}

type InboundClientIps struct {
	Id          int    `json:"id" gorm:"primaryKey;autoIncrement"`
	ClientEmail string `json:"clientEmail" form:"clientEmail" gorm:"unique"`
	Ips         string `json:"ips" form:"ips"`
}

func (i *Inbound) GenXrayInboundConfig() *xray.InboundConfig {
	listen := i.Listen
	if listen != "" {
		listen = fmt.Sprintf("\"%v\"", listen)
	}
	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(listen),
		Port:           i.Port,
		Protocol:       string(i.Protocol),
		Settings:       json_util.RawMessage(i.Settings),
		StreamSettings: json_util.RawMessage(i.StreamSettings),
		Tag:            i.Tag,
		Sniffing:       json_util.RawMessage(i.Sniffing),
	}
}

type Setting struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Key   string `json:"key" form:"key"`
	Value string `json:"value" form:"value"`
}

type Client struct {
	ID         string `json:"id"`
	Password   string `json:"password"`
	Flow       string `json:"flow"`
	Email      string `json:"email"`
	LimitIP    int    `json:"limitIp"`
	TotalGB    int64  `json:"totalGB" form:"totalGB"`
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"`
	Enable     bool   `json:"enable" form:"enable"`
	TgID       int64  `json:"tgId" form:"tgId"`
	SubID      string `json:"subId" form:"subId"`
	Reset      int    `json:"reset" form:"reset"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type TcpRequest struct {
	Version string   `json:"version"`
	Method  string   `json:"method"`
	Path    []string `json:"path"`
	Headers []Header `json:"headers"`
}

type TcpResponse struct {
	Version string   `json:"version"`
	Status  string   `json:"status"`
	Reason  string   `json:"reason"`
	Headers []Header `json:"headers"`
}

type TcpStreamSettingsHeader struct {
	Type     string      `json:"type"`
	Request  TcpRequest  `json:"request"`
	Response TcpResponse `json:"response"`
}

type TcpStreamSettings struct {
	AcceptProxyProtocol bool                    `json:"acceptProxyProtocol"`
	Header              TcpStreamSettingsHeader `json:"header"`
}

type KcpStreamSettingsHeader struct {
	Type string `json:"type"`
}

type KcpStreamSettings struct {
	Mtu         int                     `json:"mtu"`
	Tti         int                     `json:"tti"`
	UpCap       int                     `json:"upCap"`
	DownCap     int                     `json:"downCap"`
	Congestion  bool                    `json:"congestion"`
	ReadBuffer  int                     `json:"readBuffer"`
	WriteBuffer int                     `json:"writeBufferSize"`
	Header      KcpStreamSettingsHeader `json:"header"`
	Seed        string                  `json:"seed"`
}

type WsStreamSettings struct {
	AcceptProxyProtocol bool     `json:"acceptProxyProtocol"`
	Path                string   `json:"path"`
	Host                string   `json:"host"`
	Headers             []Header `json:"headers"`
}

type HttpStreamSettings struct {
	Path string   `json:"path"`
	Host []string `json:"host"`
}

type QuicStreamSettingsHeader struct {
	Type string `json:"type"`
}

type QuicStreamSettings struct {
	Security string                   `json:"security"`
	Key      string                   `json:"key"`
	Header   QuicStreamSettingsHeader `json:"header"`
}

type GrpcStreamSettings struct {
	ServiceName string `json:"serviceName"`
	Authority   string `json:"authority"`
	MultiMode   bool   `json:"multiMode"`
}

type TlsStreamSettingsSettings struct {
	AllowInsecure bool   `json:"allowInsecure"`
	Fingerprint   string `json:"fingerprint"`
}

type TlsStreamSettings struct {
	Sni              string                    `json:"sni"`
	MinVersion       string                    `json:"minVersion"`
	MaxVersion       string                    `json:"maxVersion"`
	CipherSuites     string                    `json:"cipherSuites"`
	RejectUnknownSni bool                      `json:"rejectUnknownSni"`
	Certificates     []string                  `json:"certificates"`
	Alpn             []string                  `json:"alpn"`
	Settings         TlsStreamSettingsSettings `json:"settings"`
}

type XtlsStreamSettingsSettings struct {
	AllowInsecure bool `json:"allowInsecure"`
}

//type XtlsStreamSettingsCert struct {
//
//}

type XtlsStreamSettings struct {
	ServerName   string                     `json:"serverName"`
	Certificates []string                   `json:"certificates"`
	Alpn         []string                   `json:"alpn"`
	Settings     XtlsStreamSettingsSettings `json:"settings"`
}

type RealityStreamSettingsSettings struct {
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
	ServerName  string `json:"serverName"`
	SpiderX     string `json:"spiderX"`
}

type RealityStreamSettings struct {
	Show        bool                          `json:"show"`
	Xver        float64                       `json:"xver"`
	Dest        string                        `json:"dest"`
	ServerNames []string                      `json:"serverNames"`
	PrivateKey  string                        `json:"privateKey"`
	MinClient   string                        `json:"minClient"`
	MaxClient   string                        `json:"maxClient"`
	MaxTimediff float64                       `json:"maxTimediff"`
	ShortIds    []string                      `json:"shortIds"`
	Settings    RealityStreamSettingsSettings `json:"settings"`
}

type HttpUpgradeStreamSettings struct {
	AcceptProxyProtocol bool     `json:"acceptProxyProtocol"`
	Path                string   `json:"path"`
	Host                string   `json:"host"`
	Headers             []Header `json:"headers"`
}

type SockoptStreamSettings struct {
	AcceptProxyProtocol bool    `json:"acceptProxyProtocol"`
	TcpFastOpen         bool    `json:"tcpFastOpen"`
	Mark                float64 `json:"mark"`
	TProxy              string  `json:"tproxy"`
}

type StreamSettings struct {
	Network       string                    `json:"network"`
	Security      string                    `json:"security"`
	ExternalProxy []string                  `json:"externalProxy"`
	Tls           TlsStreamSettings         `json:"tlsSettings"`
	Xtls          XtlsStreamSettings        `json:"xtlsSettings"`
	Reality       RealityStreamSettings     `json:"realitySettings"`
	Tcp           TcpStreamSettings         `json:"tcpSettings"`
	Kcp           KcpStreamSettings         `json:"kcpSettings"`
	Ws            WsStreamSettings          `json:"wsSettings"`
	Http          HttpStreamSettings        `json:"httpSettings"`
	Quic          QuicStreamSettings        `json:"quicSettings"`
	Grpc          GrpcStreamSettings        `json:"grpcSettings"`
	HttpUpgrade   HttpUpgradeStreamSettings `json:"httpupgradeSettings"`
	Sockopt       SockoptStreamSettings     `json:"sockopt"`
}

type ShadowsocksSettings struct {
	Method   string `json:"method"`
	Password string `json:"password"`
	Network  string `json:"network"`
}
