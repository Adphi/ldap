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

	DefaultEncoder Encoder = &encoder{useInterface: true}
	DefaultDecoder Decoder = &decoder{useInterface: true}
)

type Marshaler interface {
	MarshalLDAP() (*Entry, error)
}

type Unmarshaler interface {
	UnmarshalLDAP(e *Entry) error
}

type Encoder interface {
	Encode(v interface{}) (*Entry, error)
}

func NewEncoder(useInterface bool) Encoder {
	return &encoder{useInterface: useInterface}
}

type Decoder interface {
	Decode(e *Entry, v interface{}) error
}

func NewDecoder(useInterface bool) Decoder {
	return &decoder{useInterface: useInterface}
}

func Marshal(v interface{}) (*Entry, error) {
	return DefaultEncoder.Encode(v)
}

func MarshalSlice(v interface{}) ([]*Entry, error) {
	if v == nil {
		return nil, errors.New("v is nil")
	}
	vv := reflect.ValueOf(v)
	if vv.Kind() != reflect.Slice {
		return nil, errors.New("v is not a slice pointer")
	}
	var out []*Entry
	for i := 0; i < vv.Len(); i++ {
		e, err := Marshal(vv.Index(i).Interface())
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func Unmarshal(e *Entry, v interface{}) error {
	return DefaultDecoder.Decode(e, v)
}

func UnmarshalSlice(entries []*Entry, v interface{}) error {
	if v == nil {
		return errors.New("v is nil")
	}
	t := reflect.TypeOf(v)
	if t.Kind() != reflect.Ptr {
		return ErrNotPointer
	}
	t = t.Elem()
	if t.Kind() != reflect.Slice {
		return errors.New("v is not a slice pointer")
	}
	vv := reflect.ValueOf(v).Elem()
	for _, e := range entries {
		var ev reflect.Value
		if t.Elem().Kind() == reflect.Ptr {
			ev = reflect.New(t.Elem().Elem())
		} else {
			ev = reflect.New(t.Elem())
		}
		if err := Unmarshal(e, ev.Interface()); err != nil {
			return err
		}
		if t.Elem().Kind() == reflect.Ptr {
			vv.Set(reflect.Append(vv, ev))
		} else {
			vv.Set(reflect.Append(vv, ev.Elem()))
		}
	}
	return nil
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
	readOnly  bool
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
		if strings.TrimSpace(v) == "ro" {
			fi.readOnly = true
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
		if ft.Anonymous && hasDN(v.Field(i)) {
			return true
		}
	}
	return false
}
