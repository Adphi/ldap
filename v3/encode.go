package ldap

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

type encoder struct{}

func (e *encoder) Encode(v interface{}) (*Entry, error) {
	if v == nil {
		return nil, errors.New("v is nil")
	}
	if m, ok := v.(Marshaler); ok {
		return m.MarshalLDAP()
	}
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, errors.New("cannot decode non struct type")
	}
	rt := rv.Type()
	attrs, dn, err := encodeStructFields(rv, rt)
	if err != nil {
		return nil, err
	}
	if dn == "" {
		return nil, ErrNoDN
	}
	entry := &Entry{
		DN:         dn,
		Attributes: attrs,
	}
	return entry, nil
}

func encodeStructFields(v reflect.Value, t reflect.Type) (attrs []*EntryAttribute, dn string, err error) {
	for i := 0; i < v.NumField(); i++ {
		fv := v.Field(i)
		ft := t.Field(i)
		info := parseTag(ft)
		if info.ignored {
			continue
		}
		if fv.IsZero() && strings.ToLower(info.attrName) != "dn" {
			if info.omitempty {
				continue
			}
			//attrs = append(attrs, emptyAttr(info.attrName))
			//continue
		}
		if fv.Kind() == reflect.Ptr && fv.IsNil() {
			attrs = append(attrs, emptyAttr(info.attrName))
			continue
		}
		if ft.Anonymous {
			as, d, err := encodeStructFields(fv, fv.Type())
			if err != nil {
				return nil, "", err
			}
			if d != "" {
				dn = d
			}
			attrs = append(attrs, as...)
			continue
		}
		var (
			attr *EntryAttribute
			d    string
		)
		attr, d, err = encodeField(info.attrName, fv, info.omitempty)
		if err != nil {
			return
		}
		if d != "" {
			dn = d
			continue
		}
		if attr == nil {
			attr = emptyAttr(info.attrName)
		}
		attrs = append(attrs, attr)
		continue
	}
	return
}

func encodeField(attrName string, fv reflect.Value, omitEmpty bool) (attr *EntryAttribute, dn string, err error) {
	if omitEmpty {
		if fv.IsZero() {
			return
		}
	}
	if strings.ToLower(attrName) == "dn" {
		switch f := fv.Interface().(type) {
		case string:
			dn = f
		case []byte:
			dn = string(f)
		default:
			err = fmt.Errorf("%w: %s", ErrUnsupportedDNType, fv.Type().Name())
		}
		return
	}
	switch f := fv.Interface().(type) {
	case BinaryEncoder:
		var b []byte
		b, err = f.Encode()
		if err != nil {
			return
		}
		attr = NewEntryAttribute(attrName, []string{string(b)})
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		attr = NewEntryAttribute(attrName, []string{fmt.Sprintf("%d", f)})
	case float32, float64:
		attr = NewEntryAttribute(attrName, []string{fmt.Sprintf("%f", f)})
	case string:
		attr = NewEntryAttribute(attrName, []string{f})
	case []byte:
		attr = NewEntryAttribute(attrName, []string{string(f)})
	}
	if attr != nil {
		return
	}
	if fv.Kind() == reflect.Slice {
		for i := 0; i < fv.Len(); i++ {
			var a *EntryAttribute
			a, _, err = encodeField(attrName, fv.Index(i), true)
			if err != nil {
				return
			}
			if attr == nil {
				attr = a
				continue
			}
			attr.Values = append(attr.Values, a.Values...)
			attr.ByteValues = append(attr.ByteValues, a.ByteValues...)
		}
		if attr == nil {
			attr = emptyAttr(attrName)
		}
		return
	}
	for fv.Kind() == reflect.Ptr {
		return encodeField(attrName, fv.Elem(), omitEmpty)
	}
	err = fmt.Errorf("%w for %s", ErrUnsupportedType, attrName)
	return
}

func emptyAttr(name string) *EntryAttribute {
	return &EntryAttribute{Name: name, Values: []string{}, ByteValues: [][]byte{}}
}
