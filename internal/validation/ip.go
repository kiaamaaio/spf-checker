package validation

import "net"

// ParseIP は ipaddr を IP アドレスとして解釈する。IPv4 と IPv6 のどちらでも
// 受け付け、どちらとしても解釈できない場合は ErrInvalidIpAddress を返す。
//
// net.ParseIP は失敗を nil で表すため、呼び出し側が戻り値の nil 検査を
// 忘れないようにエラーへ変換している。
func ParseIP(ipaddr string) (net.IP, error) {
	parsedIP := net.ParseIP(ipaddr)
	if parsedIP == nil {
		return nil, ErrInvalidIpAddress
	}
	return parsedIP, nil
}
