package security

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[PKCS1WithSHA256-1025]
	_ = x[PKCS1WithSHA384-1281]
	_ = x[PKCS1WithSHA512-1537]
	_ = x[PSSWithSHA256-2052]
	_ = x[PSSWithSHA384-2053]
	_ = x[PSSWithSHA512-2054]
	_ = x[ECDSAWithP256AndSHA256-1027]
	_ = x[ECDSAWithP384AndSHA384-1283]
	_ = x[ECDSAWithP521AndSHA512-1539]
	_ = x[Ed25519-2055]
	_ = x[PKCS1WithSHA1-513]
	_ = x[ECDSAWithSHA1-515]
}

const (
	_SignatureScheme_name_0 = "PKCS1WithSHA1"
	_SignatureScheme_name_1 = "ECDSAWithSHA1"
	_SignatureScheme_name_2 = "PKCS1WithSHA256"
	_SignatureScheme_name_3 = "ECDSAWithP256AndSHA256"
	_SignatureScheme_name_4 = "PKCS1WithSHA384"
	_SignatureScheme_name_5 = "ECDSAWithP384AndSHA384"
	_SignatureScheme_name_6 = "PKCS1WithSHA512"
	_SignatureScheme_name_7 = "ECDSAWithP521AndSHA512"
	_SignatureScheme_name_8 = "PSSWithSHA256PSSWithSHA384PSSWithSHA512Ed25519"
)

var (
	_SignatureScheme_index_8 = [...]uint8{0, 13, 26, 39, 46}
)

func (i SignatureScheme) String() string {
	switch {
	case i == 513:
		return _SignatureScheme_name_0
	case i == 515:
		return _SignatureScheme_name_1
	case i == 1025:
		return _SignatureScheme_name_2
	case i == 1027:
		return _SignatureScheme_name_3
	case i == 1281:
		return _SignatureScheme_name_4
	case i == 1283:
		return _SignatureScheme_name_5
	case i == 1537:
		return _SignatureScheme_name_6
	case i == 1539:
		return _SignatureScheme_name_7
	case 2052 <= i && i <= 2055:
		i -= 2052
		return _SignatureScheme_name_8[_SignatureScheme_index_8[i]:_SignatureScheme_index_8[i+1]]
	default:
		return "SignatureScheme(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[CurveP256-23]
	_ = x[CurveP384-24]
	_ = x[CurveP521-25]
	_ = x[X25519-29]
}

const (
	_CurveID_name_0 = "CurveP256CurveP384CurveP521"
	_CurveID_name_1 = "X25519"
)

var (
	_CurveID_index_0 = [...]uint8{0, 9, 18, 27}
)

func (i CurveID) String() string {
	switch {
	case 23 <= i && i <= 25:
		i -= 23
		return _CurveID_name_0[_CurveID_index_0[i]:_CurveID_index_0[i+1]]
	case i == 29:
		return _CurveID_name_1
	default:
		return "CurveID(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[NoClientCert-0]
	_ = x[RequestClientCert-1]
	_ = x[RequireAnyClientCert-2]
	_ = x[VerifyClientCertIfGiven-3]
	_ = x[RequireAndVerifyClientCert-4]
}

const _ClientAuthType_name = "NoClientCertRequestClientCertRequireAnyClientCertVerifyClientCertIfGivenRequireAndVerifyClientCert"

var _ClientAuthType_index = [...]uint8{0, 12, 29, 49, 72, 98}

func (i ClientAuthType) String() string {
	if i < 0 || i >= ClientAuthType(len(_ClientAuthType_index)-1) {
		return "ClientAuthType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _ClientAuthType_name[_ClientAuthType_index[i]:_ClientAuthType_index[i+1]]
}
