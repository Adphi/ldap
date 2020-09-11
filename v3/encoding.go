package ldap

import (
	"errors"
	"reflect"
	"strings"
	"unicode"
)

var (
	ErrNotPointer        = errors.New("v must be a pointer")
	ErrUnsupportedDNType = errors.New("unsupported DN type")
	ErrUnsupportedType   = errors.New("unsupported type")
	ErrNoDN              = errors.New("no DN found")
)

type Marshaler interface {
	MarshalLDAP() (*Entry, error)
}

type Unmarshaler interface {
	UnmarshalLDAP() error
}

type Encoder interface {
	Encode(v interface{}) (*Entry, error)
}

func NewEncoder() Encoder {
	return &encoder{}
}

type Decoder interface {
	Decode(v interface{}) error
}

func NewDecoder(e *Entry) Decoder {
	return &decoder{e: e}
}

func Marshal(v interface{}) (*Entry, error) {
	return (&encoder{}).Encode(v)
}

func Unmarshal(e *Entry, v interface{}) error {
	return (&decoder{e}).Decode(v)
}

type BinaryEncoder interface {
	Encode() ([]byte, error)
}

type BinaryDecoder interface {
	Decode([]byte) error
}

type info struct {
	attrName  string
	ignored   bool
	omitempty bool
}

func parseTag(sf reflect.StructField) info {
	name := string(unicode.ToLower(rune(sf.Name[0]))) + sf.Name[1:]
	if len(name) == 2 {
		name = strings.ToLower(name)
	}
	fi := info{
		attrName: name,
		ignored:  false,
	}
	t, ok := sf.Tag.Lookup("ldap")
	if !ok {
		return fi
	}
	parts := strings.Split(t, ",")
	if len(parts) == 0 {
		return fi
	}
	if strings.TrimSpace(parts[0]) == "-" {
		fi.ignored = true
		return fi
	}
	fi.attrName = parts[0]
	for _, v := range parts {
		if strings.TrimSpace(v) == "omitempty" {
			fi.omitempty = true
		}
	}
	return fi
}

func hasDN(v reflect.Value) bool {
	for v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < v.NumField(); i++ {
		ft := v.Type().Field(i)
		info := parseTag(ft)
		if info.attrName == "dn" {
			return true
		}
		if ft.Anonymous && hasDN(v.Field(i)){
			return true
		}
	}
	return false
}
